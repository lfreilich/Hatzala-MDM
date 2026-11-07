"""Play Store page: fetch an app's APK from Google Play with a signed-in Google account, then publish it in Headwind.

Downloads go through apkeep (EFF, MIT licence, baked into the image at APKEEP_BIN). Google no longer accepts
passwords from tools like this, so the account is connected once with an oauth_token taken from Google's
EmbeddedSetup sign-in page; apkeep swaps it for a long-lived AAS token that is kept in the kv table.

Use a dedicated Google account: Google can close accounts that download through unofficial clients.
Paid apps aren't available. The APK goes in APK_DIR, which Caddy serves at /apk/ for devices to install.
"""
import glob
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from pyaxmlparser import APK

from . import config, db
from .clients import Headwind

APKEEP = os.getenv("APKEEP_BIN", "/usr/local/bin/apkeep")
DEVICE = os.getenv("GPLAY_DEVICE", "px_9a")  # apkeep device profile Play serves the APK for (arm64 Pixel)
LOCALE = os.getenv("GPLAY_LOCALE", "en_US")
PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ACCOUNT_KEY = "gplay:account"  # {email, aas_token, by, added}
APPS_KEY = "gplay:apps"        # pkg -> {file, label, version, code, size, split_required, fetched, by, hmdm_id}
JOBS_KEY = "gplay:jobs"        # pkg -> {state: running|done|error, message, started}

_lock = threading.Lock()


def _redact(text: str) -> str:
    return re.sub(r"(aas_et/|oauth2_4/|ya29\.)\S+", r"\1…", text or "")


def _run(args: list[str], timeout: int) -> str:
    if not os.path.exists(APKEEP):
        raise RuntimeError("apkeep isn't installed in the bridge image. Rebuild the bridge.")
    try:
        p = subprocess.run([APKEEP, *args], capture_output=True, text=True, timeout=timeout,
                           env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir()})
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Google Play didn't finish within {timeout // 60} minutes")
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        raise RuntimeError(_redact(out.strip())[-500:] or f"apkeep exited with {p.returncode}")
    return out


# ------------------------------------------------------------------ account
def account() -> dict | None:
    a = db.kv_get(ACCOUNT_KEY)
    return {k: a[k] for k in ("email", "by", "added")} if a else None


def connect(email: str, oauth_token: str, actor: str):
    email, oauth_token = email.strip().lower(), oauth_token.strip()
    if not EMAIL_RE.match(email):
        raise ValueError("Enter the Google account's email address.")
    if not oauth_token.startswith("oauth2_4/"):
        raise ValueError("That isn't the oauth_token cookie. Its value starts with oauth2_4/")
    out = _run(["-e", email, "--oauth-token", oauth_token, "--accept-tos"], timeout=90)
    m = re.search(r"aas_et/\S+", out)
    if not m:
        raise RuntimeError("Google didn't return a token. The oauth_token works only once and expires in minutes; "
                           "sign in again and paste the new one. " + _redact(out.strip())[-300:])
    db.kv_set(ACCOUNT_KEY, {"email": email, "aas_token": m.group(0), "by": actor, "added": time.time()})
    db.log("info", f"Play Store: Google account {email} connected by {actor}")


def disconnect(actor: str):
    a = db.kv_get(ACCOUNT_KEY)
    db.x("DELETE FROM kv WHERE k=?", (ACCOUNT_KEY,))
    if a:
        db.log("info", f"Play Store: Google account {a['email']} disconnected by {actor}")


# ------------------------------------------------------------------ fetching
def apps() -> list[dict]:
    rows = db.kv_get(APPS_KEY, {})
    return sorted(({"pkg": k, **v} for k, v in rows.items()), key=lambda r: -r.get("fetched", 0))


def jobs() -> dict:
    return db.kv_get(JOBS_KEY, {})


def _set_job(pkg: str, state: str, message: str = ""):
    with _lock:
        j = db.kv_get(JOBS_KEY, {})
        j = {k: v for k, v in j.items() if v.get("state") == "running" or time.time() - v.get("started", 0) < 86400}
        prev = j.get(pkg, {})
        j[pkg] = {"state": state, "message": message[:500],
                  "started": prev.get("started", time.time()) if state != "running" else time.time()}
        db.kv_set(JOBS_KEY, j)


def _split_required(apk: APK) -> bool:
    """Bundle apps need their config splits too; a lone base.apk then won't install (or crashes)."""
    for attr in ("isSplitRequired", "requiredSplitTypes"):
        try:
            v = apk.get_attribute_value("application", attr)
        except Exception:
            v = None
        if v and str(v).lower() not in ("false", "0"):
            return True
    return False


def _fetch(pkg: str, actor: str):
    acct = db.kv_get(ACCOUNT_KEY)
    work = tempfile.mkdtemp(prefix="gplay-", dir=config.APK_DIR)
    try:
        _run(["-a", pkg, "-d", "google-play", "-e", acct["email"], "-t", acct["aas_token"], "--accept-tos",
              "-o", f"device={DEVICE},locale={LOCALE}", work], timeout=900)
        found = glob.glob(os.path.join(work, "**", "*.apk"), recursive=True)
        base = [f for f in found if os.path.basename(f) in (f"{pkg}.apk", "base.apk")] or found
        if not base:
            raise RuntimeError("Google Play returned no APK. The app may be paid, region-locked, "
                               "or not offered for this device type.")
        apk = APK(base[0])
        if apk.package != pkg:
            raise RuntimeError(f"Downloaded package is {apk.package}, expected {pkg}")
        code = int(apk.version_code)
        fname = f"{pkg}-{code}.apk"
        dest = os.path.join(config.APK_DIR, fname)
        shutil.move(base[0], dest)
        os.chmod(dest, 0o644)
        with _lock:
            rows = db.kv_get(APPS_KEY, {})
            old = rows.get(pkg, {})
            rows[pkg] = {"file": fname, "label": (apk.application or pkg)[:80], "version": apk.version_name or str(code),
                         "code": code, "size": os.path.getsize(dest), "split_required": _split_required(apk),
                         "fetched": time.time(), "by": actor, "hmdm_id": old.get("hmdm_id")}
            db.kv_set(APPS_KEY, rows)
        if old.get("file") and old["file"] != fname and not old.get("published_file") == old["file"]:
            try:
                os.remove(os.path.join(config.APK_DIR, old["file"]))
            except OSError:
                pass
        note = " (needs split APKs, may not install alone)" if rows[pkg]["split_required"] else ""
        db.log("info", f"Play Store: fetched {pkg} {rows[pkg]['version']} ({code}) for {actor}{note}")
        _set_job(pkg, "done", f"Fetched version {rows[pkg]['version']}{note}")
    except Exception as e:
        msg = _redact(str(e))
        db.log("error", f"Play Store: fetching {pkg} failed: {msg}")
        _set_job(pkg, "error", msg)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def start_fetch(pkg: str, actor: str):
    pkg = pkg.strip()
    m = re.search(r"[?&]id=([A-Za-z0-9_.]+)", pkg)  # accept a pasted play.google.com link
    if m:
        pkg = m.group(1)
    if not PKG_RE.match(pkg) or len(pkg) > 200:
        raise ValueError("Enter a package name like com.whatsapp, or paste the app's Google Play link.")
    if not db.kv_get(ACCOUNT_KEY):
        raise ValueError("Connect a Google account first.")
    if jobs().get(pkg, {}).get("state") == "running":
        raise ValueError(f"{pkg} is already downloading.")
    _set_job(pkg, "running", "Downloading from Google Play…")
    threading.Thread(target=_fetch, args=(pkg, actor), daemon=True).start()
    return pkg


def forget(pkg: str, actor: str):
    with _lock:
        rows = db.kv_get(APPS_KEY, {})
        row = rows.pop(pkg, None)
        db.kv_set(APPS_KEY, rows)
    if row and row.get("published_file") != row.get("file"):  # a published APK stays: devices install from it
        try:
            os.remove(os.path.join(config.APK_DIR, row["file"]))
        except OSError:
            pass
    db.log("info", f"Play Store: {pkg} removed from the list by {actor}")


# ------------------------------------------------------------------ Headwind
def publish(pkg: str, config_ids: list[int], actor: str) -> str:
    """Add the APK to Headwind (new app or new version) and set it to install on the chosen configurations.
    Only touches the application and its links; never PUTs a configuration."""
    rows = db.kv_get(APPS_KEY, {})
    row = rows.get(pkg)
    if not row:
        raise ValueError(f"{pkg} hasn't been fetched.")
    hw = Headwind()
    url = f"https://{config.OPS_HOST}/apk/{row['file']}"
    existing = next((a for a in hw.applications() if a.get("pkg") == pkg), None)
    if existing is None:
        app_id = hw.create_app(row["label"], pkg, row["version"], row["code"], url)["id"]
        what = f"added to Headwind as {row['label']}"
    else:
        app_id = existing["id"]
        have = {str(v.get("version")) for v in hw.app_versions(app_id)}
        if row["version"] in have:
            what = f"version {row['version']} was already in Headwind"
        else:
            hw.add_app_version(app_id, row["version"], row["code"], url)
            what = f"version {row['version']} added in Headwind"
    if config_ids:
        linked = {c["configurationId"] for c in hw.app_configurations(app_id) if c.get("action") == 1}
        missing = [c for c in config_ids if c not in linked]
        if missing:
            hw.link_app(app_id, missing)
        what += f"; installs on {len(config_ids)} configuration(s)"
    with _lock:
        rows = db.kv_get(APPS_KEY, {})
        if pkg in rows:
            rows[pkg].update(hmdm_id=app_id, published_file=row["file"], published=time.time())
            db.kv_set(APPS_KEY, rows)
    db.log("info", f"Play Store: {pkg} {row['version']} published by {actor}: {what}")
    return what
