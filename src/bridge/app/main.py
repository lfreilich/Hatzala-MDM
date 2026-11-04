"""hbs-bridge: glue between Headwind MDM (community) and the self-hosted add-ons."""
import base64
import csv
import hashlib
import io
import json
import os
import threading
import time

import httpx
import qrcode
import qrcode.image.svg
import re
from urllib.parse import urlencode
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config, db, provision, sso, walkiefleet
from .clients import Headwind

app = FastAPI(title="hbs-bridge", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
_sync_lock = threading.Lock()


# ------------------------------------------------------------------ background sync
def _sync(force_apps=False, wait=False):
    """wait=True queues behind a running sync, for changes that run must not miss."""
    if not (_sync_lock.acquire(timeout=120) if wait else _sync_lock.acquire(blocking=False)):
        return
    try:
        n = provision.sync_all(force_apps=force_apps)
        db.kv_set("last_sync_ok", time.time())
        db.kv_set("last_sync_error", None)
        print(f"sync ok: {n} devices", flush=True)
    except Exception as e:
        db.kv_set("last_sync_error", str(e))
        db.log("error", f"Sync failed: {e}")
    finally:
        _sync_lock.release()


def _loop():
    time.sleep(5)
    while True:
        _sync()
        time.sleep(config.SYNC_INTERVAL)


@app.on_event("startup")
def _start():
    os.makedirs(config.APK_DIR, exist_ok=True)
    db.conn()
    if os.getenv("BRIDGE_NO_LOOP") != "1":
        threading.Thread(target=_loop, daemon=True).start()


# ------------------------------------------------------------------ open endpoints
@app.get("/healthz")
def healthz():
    return {"ok": True, "last_sync": db.kv_get("last_sync_ok"), "error": db.kv_get("last_sync_error")}


@app.get("/prov/linphone/{token}.xml")
def linphone_provisioning(token: str):
    rows = db.q("SELECT * FROM devices WHERE prov_token=?", (token,)) if len(token) > 20 else []
    if not rows:
        time.sleep(1)
        raise HTTPException(404)
    st = dict(rows[0])
    if not (st.get("ext") and st.get("sip_secret") and config.SIP_DOMAIN):
        raise HTTPException(404)
    display = (st.get("description") or st["number"]).strip()
    db.log("info", "Linphone fetched its SIP provisioning", st["number"])
    return Response(provision.linphone_xml(st, display), media_type="application/xml",
                    headers={"Cache-Control": "no-store"})


@app.get("/signed-out", response_class=HTMLResponse)
def signed_out(request: Request):
    return templates.TemplateResponse("signed_out.html", {"request": request, "cfg": config})


@app.get("/hbs-sso")
def single_sign_on(request: Request):
    """Caddy only routes here through the gate, which sets Remote-Email. Failure falls back to the app's login."""
    email = request.headers.get("Remote-Email")
    if not email:
        raise HTTPException(403)
    host = request.headers.get("host", "").split(":")[0]
    resp = RedirectResponse("/", status_code=302, headers={"Cache-Control": "no-store"})
    try:
        for cookie in sso.login_cookies(host, email):
            resp.headers.append("set-cookie", cookie)
    except Exception as e:
        db.log("error", f"Single sign-on failed for {host}: {e}")
    return resp


# ------------------------------------------------------------------ dashboard (behind Authelia)
def _ctx(request: Request, **kw):
    return {"request": request, "cfg": config, "user": request.headers.get("Remote-Email", ""),
            "last_sync": db.kv_get("last_sync_ok"), "sync_error": db.kv_get("last_sync_error"), **kw}


DEVICE_NUMBER = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EXTENSION = re.compile(r"^[0-9]{2,6}$")


def _next_number(devices: list[dict]) -> str:
    """Next free hNNNN number, matching Headwind's own h0001 style."""
    used = {d.get("number", "") for d in devices}
    n = 1
    while f"h{n:04d}" in used:
        n += 1
    return f"h{n:04d}"


def _legacy_qr_text(number: str) -> str:
    """Headwind's enrollment QR with plain HTTP addresses, for Android too old to trust the certificate.

    Headwind has one server address for everything, so this is built here. The checksum still protects the app.
    """
    hw = Headwind()
    device = next(d for d in hw.devices() if d.get("number") == number)
    cfg = next(c for c in hw.configurations() if c["id"] == device.get("configurationId"))
    app_info = next(a for a in hw.applications() if a.get("latestVersion") == cfg["mainAppId"])
    path = app_info["url"].split("/", 3)[3]
    internal = config.HMDM_URL.rstrip("/")
    apk = httpx.get(f"{internal}/{path}", timeout=60)
    apk.raise_for_status()
    extras = httpx.get(f"{internal}/rest/public/qr/json/{cfg['qrCodeKey']}", params={"deviceId": number},
                       timeout=20).json()
    base = f"http://{config.DOMAIN}"
    extras["com.hmdm.BASE_URL"] = base
    prefix = "android.app.extra.PROVISIONING_"
    return json.dumps({
        prefix + "DEVICE_ADMIN_COMPONENT_NAME": f"{app_info['pkg']}/{cfg['eventReceivingComponent']}",
        prefix + "DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": f"{base}/{path}",
        prefix + "DEVICE_ADMIN_PACKAGE_CHECKSUM": base64.urlsafe_b64encode(hashlib.sha256(apk.content).digest()).decode(),
        prefix + "LEAVE_ALL_SYSTEM_APPS_ENABLED": True, prefix + "SKIP_ENCRYPTION": True,
        prefix + "ADMIN_EXTRAS_BUNDLE": extras}, separators=(",", ":"))


@app.get("/add-device/legacy-qr.svg")
def legacy_qr(number: str):
    try:
        text = _legacy_qr_text(number)
    except StopIteration:
        raise HTTPException(404)
    svg = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8).to_string()
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


def _register_device(number: str, user_name: str, user_email: str, ext: str):
    """Tie a new Headwind device to its user, then let sync set up their accounts."""
    st = db.device(number) or {"number": number, "steps": {}}
    st.update(user_name=user_name, user_email=user_email or None, ext=ext or None,
              nc_user=provision.user_account(user_name, number))
    db.save_device(st)
    db.log("info", f"Device created for QR enrollment, user {user_name}", number)
    threading.Thread(target=_sync, kwargs={"wait": True}, daemon=True).start()


@app.get("/add-device", response_class=HTMLResponse)
def add_device_page(request: Request, number: str = "", existed: int = 0, error: str = "", ok: str = "",
                    legacy: int = 0):
    hw = Headwind()
    devices = hw.devices()
    configs = sorted(hw.configurations(), key=lambda c: c["id"])
    current = next((d for d in devices if d.get("number") == number), None)
    chosen = next((c for c in configs if current and c["id"] == current.get("configurationId")), None)
    if chosen and not chosen.get("mainAppId"):  # Headwind answers with an empty image in this case
        error = error or f"Configuration {chosen['name']} has no main app set in Headwind, so it can't make a QR code."
    return templates.TemplateResponse("add_device.html", _ctx(
        request, configs=configs, suggested=_next_number(devices), error=error, ok=ok, legacy=legacy,
        selected=chosen["id"] if chosen else (configs[0]["id"] if configs else 0),
        number=number if chosen else "", key=chosen.get("qrCodeKey") if chosen else "",
        config_name=chosen["name"] if chosen else "", existed=existed))


@app.post("/add-device")
def add_device(number: str = Form(...), user_name: str = Form(""), user_email: str = Form(""), ext: str = Form(""),
               config_id: int = Form(...), description: str = Form("")):
    number = number.strip()
    user_name = user_name.strip()[:100]
    user_email = user_email.strip()[:254]
    ext = ext.strip()
    if not DEVICE_NUMBER.match(number):
        return RedirectResponse("/add-device?" + urlencode(
            {"error": "Use only letters, numbers, dots, dashes and underscores."}), status_code=303)
    hw = Headwind()
    existed = any(d.get("number") == number for d in hw.devices())
    if not existed:
        if not user_name:
            return RedirectResponse("/add-device?" + urlencode(
                {"error": "Enter the name of the person this device is for."}), status_code=303)
        if user_email and not EMAIL.match(user_email):
            return RedirectResponse("/add-device?" + urlencode(
                {"error": "That email address doesn't look right."}), status_code=303)
        error = ""
        if ext and not EXTENSION.match(ext):
            error = "The unit / extension should be 2 to 6 digits."
        elif ext and ext.startswith("99") and len(ext) >= 4:
            error = "99 numbers are WebRTC devices. Enter the unit's main number."
        elif ext and db.q("SELECT 1 FROM devices WHERE ext=? AND number<>?", (ext, number)):
            error = f"Another device already uses extension {ext}."
        if error:
            return RedirectResponse("/add-device?" + urlencode({"error": error}), status_code=303)
        try:
            hw.create_device(number, description.strip()[:100] or user_name, config_id)
        except Exception as e:
            db.log("error", f"Could not create device {number}: {e}")
            return RedirectResponse("/add-device?" + urlencode(
                {"error": f"Headwind refused the new device: {str(e)[:200]}"}), status_code=303)
        _register_device(number, user_name, user_email, ext)
    return RedirectResponse("/add-device?" + urlencode(
        {"number": number, "existed": int(existed)}), status_code=303)


@app.get("/link-user", response_class=HTMLResponse)
def link_user_page(request: Request, ok: str = "", error: str = ""):
    rows, exts = [], set()
    try:
        linked = {r["login"]: dict(r) for r in db.q("SELECT * FROM linked_users")}
        exts = {e["ext"] for e in provision.FreePBX().extensions()}
        for u in sorted(walkiefleet.users(), key=lambda x: x.get("Login") or ""):
            login = u.get("Login") or ""
            rows.append({"login": login, "name": u.get("Name"), "sip": u.get("SipID") or "",
                         "matchable": bool(re.fullmatch(r"[0-9]{2,6}", login)), "has_ext": login in exts,
                         "email": (linked.get(login) or {}).get("email", "")})
    except Exception as e:
        error = error or f"Could not load users: {str(e)[:200]}"
    try:
        configs = [c for c in sorted(Headwind().configurations(), key=lambda c: c["id"]) if c.get("mainAppId")]
    except Exception:
        configs = []
    return templates.TemplateResponse("link_user.html", _ctx(request, rows=rows, ok=ok, error=error, configs=configs))


@app.post("/link-user")
def link_user(login: str = Form(...), email: str = Form(""), config_id: int = Form(0)):
    email = email.strip()[:254]
    if not EMAIL.match(email):
        return RedirectResponse("/link-user?" + urlencode({"error": f"{login}: enter a valid email."}), status_code=303)
    if not config_id:
        return RedirectResponse("/link-user?" + urlencode({"error": f"{login}: choose a phone configuration."}),
                                status_code=303)
    try:
        name, result = provision.link_user(login, email)
        hw = Headwind()
        existed = any(d.get("number") == login for d in hw.devices())
        if not existed:
            hw.create_device(login, name[:100], config_id)
            _register_device(login, name[:100], email, login)
    except Exception as e:
        db.log("error", f"Link failed: {e}", login)
        return RedirectResponse("/link-user?" + urlencode({"error": f"{login}: {str(e)[:250]}"}), status_code=303)
    threading.Thread(target=_sync, kwargs={"wait": True}, daemon=True).start()
    return RedirectResponse("/add-device?" + urlencode({"number": login, "existed": int(existed), "ok": f"{login}: {result}"}),
                            status_code=303)


@app.get("/home", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", _ctx(request))


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    devices = []
    for r in db.q("SELECT * FROM devices ORDER BY number"):
        d = dict(r)
        d["steps"] = json.loads(d.get("steps") or "{}")
        devices.append(d)
    events = [dict(r) for r in db.q("SELECT * FROM events ORDER BY ts DESC LIMIT 40")]
    apks = {a: db.kv_get(f"apk:{a}") for a in config.ENABLED_APPS}
    return templates.TemplateResponse("dashboard.html", _ctx(request, devices=devices, events=events, apks=apks,
                                                               time=time))


@app.post("/sync")
def sync_now(force_apps: str = Form("")):
    threading.Thread(target=_sync, kwargs={"force_apps": bool(force_apps)}, daemon=True).start()
    return RedirectResponse("/", status_code=303)


@app.post("/device/{number}/sip")
def set_sip(number: str, ext: str = Form(""), secret: str = Form("")):
    st = db.device(number)
    if not st:
        raise HTTPException(404)
    ext = ext.strip()
    if ext != (st.get("ext") or ""):
        st.update(ext=ext or None, sip_secret=None, prov_token=None)
    if secret.strip():
        st["sip_secret"] = secret.strip()
        st["prov_token"] = None
    db.save_device(st)
    db.log("info", f"SIP extension set to {ext or '(none)'}", number)
    threading.Thread(target=_sync, daemon=True).start()
    return RedirectResponse("/", status_code=303)


ACTIONS = {
    "reboot": lambda hw, st: hw.push(st["number"], "reboot"),
    "track": provision.start_tracking,
    "nclogin": provision.send_nextcloud_login,
    "contacts": provision.send_contacts_login,
    "config": lambda hw, st: hw.push(st["number"], "configUpdated"),
    "perms": lambda hw, st: hw.push(st["number"], "grantPermissions"),
    "rustdesk": lambda hw, st: hw.push(st["number"], "runApp", {"pkg": config.PKG["rustdesk"]}),
}


@app.post("/device/{number}/action/{action}")
def device_action(number: str, action: str):
    st = db.device(number)
    if not st or action not in ACTIONS and action != "reset":
        raise HTTPException(404)
    if action == "reset":
        st["steps"] = {}
        st["prov_token"] = None
        if st.get("ext") and config.PBX_MANAGE_SECRETS:
            st["sip_secret"] = None
        db.save_device(st)
        db.log("info", "Re-provisioning requested", number)
        threading.Thread(target=_sync, daemon=True).start()
    else:
        ACTIONS[action](Headwind(), st)
        db.log("info", f"Action sent: {action}", number)
    return RedirectResponse("/", status_code=303)


@app.post("/device/{number}/delete")
def delete_device(number: str, typed: str = Form("")):
    st = db.device(number)
    if not st:
        raise HTTPException(404)
    if typed != number:
        raise HTTPException(400, "Confirmation did not match the device number.")
    if not _sync_lock.acquire(timeout=60):
        raise HTTPException(503, "A sync is still running. Try again in a minute.")
    try:
        provision.delete_device(st)
    except Exception as e:
        db.log("error", f"Could not delete device: {e}", number)
    finally:
        _sync_lock.release()
    return RedirectResponse("/", status_code=303)


# ------------------------------------------------------------------ RustDesk server QR
def _rustdesk_key() -> str:
    try:
        with open(config.RUSTDESK_KEY_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


@app.get("/rustdesk", response_class=HTMLResponse)
def rustdesk(request: Request):
    key = _rustdesk_key()
    cfg = {"host": config.RUSTDESK_HOST, "relay": f"{config.RUSTDESK_HOST}:21117", "api": "", "key": key}
    encoded = base64.urlsafe_b64encode(json.dumps(cfg, separators=(",", ":")).encode()).decode()[::-1]
    qr_text = "config=" + encoded
    svg = qrcode.make(qr_text, image_factory=qrcode.image.svg.SvgPathImage, box_size=12).to_string().decode()
    return templates.TemplateResponse("rustdesk.html", _ctx(request, key=key, qr_svg=svg, qr_text=qr_text,
                                                              host=config.RUSTDESK_HOST))


# ------------------------------------------------------------------ directory
@app.get("/directory", response_class=HTMLResponse)
def directory(request: Request):
    rows = [dict(r) for r in db.q("SELECT * FROM contacts ORDER BY name")]
    return templates.TemplateResponse("directory.html", _ctx(request, contacts=rows))


FIELDS = ("name", "org", "title", "phone", "mobile", "sip", "email", "note")


@app.post("/directory/add")
def directory_add(name: str = Form(...), org: str = Form(""), title: str = Form(""), phone: str = Form(""),
                  mobile: str = Form(""), sip: str = Form(""), email: str = Form(""), note: str = Form("")):
    db.x(f"INSERT INTO contacts({','.join(FIELDS)}) VALUES ({','.join('?' * len(FIELDS))})",
         (name.strip(), org, title, phone, mobile, sip, email, note))
    threading.Thread(target=_sync, daemon=True).start()
    return RedirectResponse("/directory", status_code=303)


@app.post("/directory/{cid}/delete")
def directory_delete(cid: int):
    db.x("DELETE FROM contacts WHERE id=?", (cid,))
    threading.Thread(target=_sync, daemon=True).start()
    return RedirectResponse("/directory", status_code=303)


@app.post("/directory/import")
async def directory_import(file: UploadFile, replace: str = Form("")):
    text = (await file.read()).decode("utf-8-sig", errors="replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    if replace:
        db.x("DELETE FROM contacts WHERE source='manual'")
    n = 0
    for r in rows:
        r = {k.strip().lower(): (v or "").strip() for k, v in r.items() if k}
        if not r.get("name"):
            continue
        db.x(f"INSERT INTO contacts({','.join(FIELDS)}) VALUES ({','.join('?' * len(FIELDS))})",
             tuple(r.get(f, "") for f in FIELDS))
        n += 1
    db.log("info", f"Imported {n} contacts from CSV")
    threading.Thread(target=_sync, daemon=True).start()
    return RedirectResponse("/directory", status_code=303)


@app.get("/directory/export.csv")
def directory_export():
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS)
    w.writeheader()
    for r in db.q("SELECT * FROM contacts ORDER BY name"):
        w.writerow({f: r[f] for f in FIELDS})
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=hbs-directory.csv"})
