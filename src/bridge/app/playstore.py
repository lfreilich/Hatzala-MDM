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


def _label(apk: APK, pkg: str) -> str:
    """App name from resources.arsc; pyaxmlparser can't parse some (e.g. WhatsApp's), so fall back to the package."""
    try:
        name = (apk.application or "").strip()
    except Exception:
        name = ""
    return (name if name and not name.startswith("@") else pkg)[:80]


def _download(pkg: str, work: str) -> tuple[str, APK]:
    """Fetch the current Play version of pkg into work; returns (base apk path, parsed APK)."""
    acct = db.kv_get(ACCOUNT_KEY)
    if not acct:
        raise RuntimeError("No Google account is connected.")
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
    return base[0], apk


def _store(pkg: str, path: str, apk: APK, actor: str) -> dict:
    """Move a downloaded APK into APK_DIR and record it; drops the previous file unless devices still use it."""
    code = int(apk.version_code)
    fname = f"{pkg}-{code}.apk"
    dest = os.path.join(config.APK_DIR, fname)
    shutil.move(path, dest)
    os.chmod(dest, 0o644)
    with _lock:
        rows = db.kv_get(APPS_KEY, {})
        old = rows.get(pkg, {})
        row = {**old, "file": fname, "label": _label(apk, pkg), "version": apk.version_name or str(code),
               "code": code, "size": os.path.getsize(dest), "split_required": _split_required(apk),
               "fetched": time.time(), "by": actor}
        rows[pkg] = row
        db.kv_set(APPS_KEY, rows)
    if old.get("file") and old["file"] != fname and old.get("published_file") != old["file"]:
        try:
            os.remove(os.path.join(config.APK_DIR, old["file"]))
        except OSError:
            pass
    return row


def _fetch(pkg: str, actor: str):
    work = tempfile.mkdtemp(prefix="gplay-", dir=config.APK_DIR)
    try:
        path, apk = _download(pkg, work)
        row = _store(pkg, path, apk, actor)
        note = " (needs split APKs, may not install alone)" if row["split_required"] else ""
        db.log("info", f"Play Store: fetched {pkg} {row['version']} ({row['code']}) for {actor}{note}")
        _set_job(pkg, "done", f"Fetched version {row['version']}{note}")
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
def _upgrade_links(hw: Headwind, app_id: int, only: list[int] | None = None) -> list[str]:
    """Move configurations that install this app (action 1) from an older version onto the newest one, and tell
    their phones to re-read the configuration so they install it now. Returns the configuration names moved."""
    moved, cfg_ids = [], set()
    for link in hw.app_configurations(app_id):
        cid = link.get("configurationId")
        if link.get("action") == 1 and link.get("outdated") and (only is None or cid in only):
            hw.upgrade_config_app(cid, app_id)
            moved.append(link.get("configurationName") or str(cid))
            cfg_ids.add(cid)
    if cfg_ids:
        for d in hw.devices():
            if d.get("configurationId") in cfg_ids and d.get("number"):
                try:
                    hw.push(d["number"], "configUpdated")
                except Exception:
                    pass  # the phone picks the change up on its next scheduled check anyway
    return moved


def publish(pkg: str, config_ids: list[int], actor: str) -> str:
    """Add the APK to Headwind (new app or new version) and set it to install on the chosen configurations.
    Only touches the application, its links and their version; never PUTs a configuration."""
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
    moved = _upgrade_links(hw, app_id, config_ids or None) if existing else []
    if moved:
        what += f"; {', '.join(moved)} moved to {row['version']}"
    with _lock:
        rows = db.kv_get(APPS_KEY, {})
        if pkg in rows:
            rows[pkg].update(hmdm_id=app_id, published_file=row["file"], published=time.time())
            db.kv_set(APPS_KEY, rows)
    db.log("info", f"Play Store: {pkg} {row['version']} published by {actor}: {what}")
    return what


# ------------------------------------------------------------------ update check
UPDATE_HOURS = float(os.getenv("GPLAY_UPDATE_HOURS", "24"))  # how often the automatic check runs
AUTO_KEY = "gplay:auto_update"   # bool, default on
CHECK_KEY = "gplay:last_check"   # {at, by, state: running|done, summary}
NOTICE_KEY = "gplay:updates"     # [{pkg, label, from, to, at, result, ok}] newest first; shown until dismissed
_check_lock = threading.Lock()


def auto_enabled() -> bool:
    return db.kv_get(AUTO_KEY, True) is not False


def set_auto(on: bool, actor: str):
    db.kv_set(AUTO_KEY, bool(on))
    db.log("info", f"Play Store: automatic updates turned {'on' if on else 'off'} by {actor}")


def last_check() -> dict | None:
    return db.kv_get(CHECK_KEY)


def notices() -> list[dict]:
    return db.kv_get(NOTICE_KEY, [])


def dismiss_notices(actor: str):
    db.kv_set(NOTICE_KEY, [])


def _notify(item: dict):
    with _lock:
        n = db.kv_get(NOTICE_KEY, [])
        db.kv_set(NOTICE_KEY, ([item] + n)[:50])


def _check_one(pkg: str, actor: str) -> str:
    """Download pkg's current Play version; if it is newer than ours, keep it and roll it out where the old one was.
    Returns a one-line result."""
    old = db.kv_get(APPS_KEY, {}).get(pkg)
    if not old:
        return "not in the list"
    _set_job(pkg, "running", "Checking Google Play for a newer version…")
    work = tempfile.mkdtemp(prefix="gplay-", dir=config.APK_DIR)
    try:
        path, apk = _download(pkg, work)
        code = int(apk.version_code)
        if code <= int(old.get("code") or 0):
            _set_job(pkg, "done", f"Up to date ({old['version']})")
            return f"up to date ({old['version']})"
        row = _store(pkg, path, apk, actor)
        frm, to = old.get("version"), row["version"]
        ok = True
        if not old.get("hmdm_id"):
            result = "new version downloaded; this app isn't in Headwind, so press Publish to roll it out"
        elif row["split_required"]:
            ok = False
            result = ("new version downloaded but NOT rolled out: Google now ships it as split APKs, "
                      "which won't install alone. Phones keep " + str(frm))
        else:
            result = publish(pkg, [], actor)
        _notify({"pkg": pkg, "label": row["label"], "from": frm, "to": to, "at": time.time(),
                 "result": result, "ok": ok})
        db.log("info" if ok else "warning", f"Play Store update: {pkg} {frm} -> {to}: {result}")
        _set_job(pkg, "done", f"Updated {frm} → {to}")
        return f"{frm} → {to}: {result}"
    except Exception as e:
        msg = _redact(str(e))
        db.log("error", f"Play Store update check for {pkg} failed: {msg}")
        _set_job(pkg, "error", f"Update check failed: {msg}")
        return f"check failed: {msg[:200]}"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_updates(actor: str) -> dict:
    """Check every app on the list against Google Play; download, publish and roll out any newer version.
    Runs in the calling thread; returns {pkg: result}."""
    if not _check_lock.acquire(blocking=False):
        raise ValueError("An update check is already running.")
    try:
        db.kv_set(CHECK_KEY, {"at": time.time(), "by": actor, "state": "running", "summary": ""})
        results = {}
        if db.kv_get(ACCOUNT_KEY):
            for pkg in list(db.kv_get(APPS_KEY, {})):
                if jobs().get(pkg, {}).get("state") == "running":
                    results[pkg] = "skipped: a download is already running"
                    continue
                results[pkg] = _check_one(pkg, actor)
        updated = sum(1 for r in results.values() if "→" in r)
        failed = sum(1 for r in results.values() if r.startswith("check failed"))
        summary = (f"{len(results)} app(s) checked, {updated} updated" + (f", {failed} failed" if failed else "")
                   if db.kv_get(ACCOUNT_KEY) else "No Google account connected")
        db.kv_set(CHECK_KEY, {"at": time.time(), "by": actor, "state": "done", "summary": summary})
        db.log("info", f"Play Store update check by {actor}: {summary}")
        return results
    finally:
        _check_lock.release()


def start_check(actor: str):
    if not db.kv_get(ACCOUNT_KEY):
        raise ValueError("Connect a Google account first.")
    if _check_lock.locked():
        raise ValueError("An update check is already running.")
    threading.Thread(target=lambda: _safe_check(actor), daemon=True).start()


def _safe_check(actor: str):
    try:
        check_updates(actor)
    except Exception as e:
        db.log("error", f"Play Store update check failed: {_redact(str(e))}")


def _auto_loop():
    time.sleep(120)
    while True:
        try:
            last = (db.kv_get(CHECK_KEY) or {}).get("at", 0)
            if auto_enabled() and db.kv_get(ACCOUNT_KEY) and time.time() - last >= UPDATE_HOURS * 3600:
                _safe_check("automatic check")
        except Exception as e:
            print(f"playstore auto-update: {e}", flush=True)
        time.sleep(600)


def start_auto_updates():
    c = db.kv_get(CHECK_KEY)
    if c and c.get("state") == "running":  # the bridge restarted mid-check
        db.kv_set(CHECK_KEY, {**c, "state": "done", "summary": "interrupted by a restart"})
    j = db.kv_get(JOBS_KEY, {})
    if any(v.get("state") == "running" for v in j.values()):
        db.kv_set(JOBS_KEY, {k: ({**v, "state": "error", "message": "Interrupted by a restart"}
                                 if v.get("state") == "running" else v) for k, v in j.items()})
    if UPDATE_HOURS > 0:
        threading.Thread(target=_auto_loop, daemon=True).start()
