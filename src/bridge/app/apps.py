"""Mirror add-on APKs locally and register them in Headwind so they install over the air."""
import os
import re
import time

import httpx
from pyaxmlparser import APK

from . import config, db
from .clients import Headwind

FDROID_API = "https://f-droid.org/api/v1/packages/{pkg}"
FDROID_APK = "https://f-droid.org/repo/{pkg}_{code}.apk"
UA = {"User-Agent": "hbs-bridge/1.0"}


def _latest_url(app: str) -> str:
    """Source of the newest stable APK. Override any with APK_URL_<APP> in .env."""
    override = os.getenv(f"APK_URL_{app.upper()}")
    if override:
        return override
    pkg = config.PKG[app]
    if app == "traccar":
        # Not on F-Droid any more; official APK is a stable-named GitHub release asset
        return "https://github.com/traccar/traccar-client/releases/latest/download/app-release.apk"
    if app == "rustdesk":
        # Official universal build from GitHub (F-Droid ships per-ABI builds); fall back to F-Droid
        try:
            r = httpx.get("https://api.github.com/repos/rustdesk/rustdesk/releases/latest", headers=UA, timeout=30)
            r.raise_for_status()
            assets = r.json().get("assets", [])
            for pattern in (r"universal.*\.apk$", r"(aarch64|arm64).*\.apk$"):
                for a in assets:
                    if re.search(pattern, a["name"]):
                        return a["browser_download_url"]
        except Exception as e:
            db.log("warn", f"RustDesk GitHub lookup failed ({e}), using F-Droid")
    r = httpx.get(FDROID_API.format(pkg=pkg), headers=UA, timeout=30)
    r.raise_for_status()
    code = r.json()["suggestedVersionCode"]
    return FDROID_APK.format(pkg=pkg, code=code)


def _download(url: str, dest: str):
    tmp = dest + ".part"
    with httpx.stream("GET", url, headers=UA, timeout=300, follow_redirects=True) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes(1 << 16):
                f.write(chunk)
    os.replace(tmp, dest)


def mirror(app: str) -> dict:
    """Download the APK if new. Returns {file, version, code, pkg}."""
    os.makedirs(config.APK_DIR, exist_ok=True)
    url = _latest_url(app)
    state = db.kv_get(f"apk:{app}") or {}
    fresh = time.time() - state.get("checked", 0) < 7 * 86400
    if state.get("source") == url and fresh and os.path.exists(os.path.join(config.APK_DIR, state.get("file", ""))):
        return state
    tmp = os.path.join(config.APK_DIR, f"{app}.download.apk")
    _download(url, tmp)
    apk = APK(tmp)
    pkg, version, code = apk.package, apk.version_name, int(apk.version_code)
    if pkg != config.PKG[app]:
        os.remove(tmp)
        raise RuntimeError(f"{app}: downloaded package is {pkg}, expected {config.PKG[app]}")
    fname = f"{pkg}-{code}.apk"
    os.replace(tmp, os.path.join(config.APK_DIR, fname))
    new = state.get("code") != code
    state = {"file": fname, "version": version, "code": code, "pkg": pkg, "source": url, "checked": time.time()}
    db.kv_set(f"apk:{app}", state)
    if new:
        db.log("info", f"Mirrored {app} {version} ({code})")
    return state


def target_config_ids(hw: Headwind) -> list[int]:
    if config.HMDM_CONFIG_IDS.strip().lower() == "all":
        return [c["id"] for c in hw.configurations()]
    return [int(x) for x in config.HMDM_CONFIG_IDS.split(",") if x.strip()]


def register_all(hw: Headwind) -> dict[str, int]:
    """Make sure every enabled add-on app exists in Headwind and is installed by the target configurations.
    Returns pkg -> Headwind application id."""
    result = {}
    cfg_ids = target_config_ids(hw)
    apps_by_pkg = {a["pkg"]: a for a in hw.applications() if a.get("pkg")}
    for app in config.ENABLED_APPS:
        pkg = config.PKG[app]
        try:
            existing = apps_by_pkg.get(pkg)
            try:
                st = mirror(app)
            except Exception as e:
                if existing is None:
                    raise
                # Keep using the version already in Headwind (e.g. uploaded by hand)
                db.log("warn", f"{app}: couldn't fetch a new APK ({e}); keeping the version in Headwind")
                st = None
            if st is None:
                app_id = existing["id"]
            elif existing is None:
                url = f"https://{config.OPS_HOST}/apk/{st['file']}"
                created = hw.create_app(config.APP_LABEL[app], st["pkg"], st["version"], st["code"], url)
                app_id = created["id"]
                db.log("info", f"Registered {app} {st['version']} in Headwind (app id {app_id})")
            else:
                url = f"https://{config.OPS_HOST}/apk/{st['file']}"
                app_id = existing["id"]
                if (existing.get("version") or "") != st["version"]:
                    hw.add_app_version(app_id, st["version"], st["code"], url)
                    db.log("info", f"Added {app} version {st['version']} in Headwind")
            linked = {c["configurationId"] for c in hw.app_configurations(app_id) if c.get("action") == 1}
            missing = [c for c in cfg_ids if c not in linked]
            if missing:
                hw.link_app(app_id, missing)
                db.log("info", f"{app}: set to install on configurations {missing}")
            result[pkg] = app_id
        except Exception as e:  # keep going with the other apps
            db.log("error", f"App bootstrap failed for {app}: {e}")
    return result
