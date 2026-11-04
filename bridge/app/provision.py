"""Per-device over-the-air provisioning and directory sync."""
import hashlib
import json
import re
import secrets
import string
import time
from xml.sax.saxutils import escape

from . import apps, config, db, walkiefleet
from .clients import ElevenLabs, FreePBX, Headwind, Nextcloud, Traccar

PKG = config.PKG


def _pw(n=24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _enabled(app: str) -> bool:
    return app in config.ENABLED_APPS


def _installed(dev: dict) -> set[str]:
    info = dev.get("info") or {}
    return {a.get("pkg") for a in (info.get("applications") or []) if a.get("pkg")}


def _name(dev: dict) -> str:
    desc = (dev.get("description") or "").strip()
    return f"{dev['number']} - {desc}" if desc and desc != dev["number"] else dev["number"]


# ---------------------------------------------------------------- managed configurations
def managed_configs(st: dict) -> dict[str, dict]:
    """pkg -> managed configuration bundle delivered by the Headwind launcher (setApplicationRestrictions)."""
    out = {}
    if _enabled("traccar"):
        out[PKG["traccar"]] = {
            "id": st["number"],
            "url": f"https://{config.TRACK_HOST}",
            "interval": config.TRACKING_INTERVAL,
            "distance": 0,
            "angle": 30,
            "heartbeat": 300,
            "accuracy": "high",
            "buffer": True,
            "wakelock": True,
            "stop_detection": True,
        }
    if _enabled("linphone") and st.get("prov_token") and st.get("ext") and st.get("sip_secret"):
        out[PKG["linphone"]] = {"configUri": f"https://{config.OPS_HOST}/prov/linphone/{st['prov_token']}.xml"}
    if _enabled("nextcloud"):
        out[PKG["nextcloud"]] = {"base_url": f"https://{config.NC_HOST}", "disable_multiaccount": True,
                                 "disable_intro": True}
    return out


def apply_managed_configs(hw: Headwind, dev: dict, st: dict, app_ids: dict[str, int]) -> bool:
    wanted = managed_configs(st)
    current = hw.device_app_settings(dev["id"])
    keep = [s for s in current if not (s.get("name") == "managedConfig" and s.get("applicationPkg") in wanted)]
    new = []
    for pkg, bundle in wanted.items():
        app_id = app_ids.get(pkg)
        if not app_id:
            continue
        new.append({"applicationId": app_id, "applicationPkg": pkg, "name": "managedConfig", "type": "STRING",
                    "value": json.dumps(bundle, separators=(",", ":")), "readonly": True,
                    "comment": "Managed by hbs-bridge"})
    old = {(s.get("applicationPkg"), s.get("value")) for s in current
           if s.get("name") == "managedConfig" and s.get("applicationPkg") in wanted}
    if old == {(s["applicationPkg"], s["value"]) for s in new}:
        return False
    payload = [{k: v for k, v in s.items() if k in ("id", "applicationId", "name", "type", "value", "comment",
                                                     "readonly")} for s in keep] + \
              [{k: v for k, v in s.items() if k != "applicationPkg"} for s in new]
    hw.save_device_app_settings(dev["id"], payload)
    db.log("info", f"Pushed managed config for {', '.join(p for p in wanted if app_ids.get(p))}", st["number"])
    return True


# ---------------------------------------------------------------- one-time pushes
def nextcloud_login_uri(st: dict) -> str:
    return (f"nc://login/server:https://{config.NC_HOST}&user:{st['nc_user']}"
            f"&password:{st['nc_app_password']}")


def send_nextcloud_login(hw: Headwind, st: dict):
    hw.push(st["number"], "intent", {"action": "android.intent.action.VIEW", "data": nextcloud_login_uri(st)})


def send_contacts_login(hw: Headwind, st: dict):
    hw.push(st["number"], "intent", {
        "action": "android.intent.action.VIEW",
        "data": f"carddavs://{config.NC_HOST}/remote.php/dav",
        "extra": {"username": st["nc_user"], "password": st["nc_app_password"]},
    })


def start_tracking(hw: Headwind, st: dict):
    hw.push(st["number"], "grantPermissions", {"pkg": [PKG["traccar"]]})
    hw.push(st["number"], "intent", {"action": "android.intent.action.VIEW",
                                      "data": "org.traccar.client://action/start"})


def run_one_time_steps(hw: Headwind, dev: dict, st: dict):
    installed = _installed(dev)
    steps = st["steps"]

    def once(key, pkg, fn):
        if steps.get(key) or pkg not in installed:
            return
        fn(hw, st)
        steps[key] = time.time()
        db.log("info", f"One-time step done: {key}", st["number"])

    if _enabled("traccar"):
        once("traccar_start", PKG["traccar"], start_tracking)
    if _enabled("linphone"):
        once("linphone_perms", PKG["linphone"],
             lambda h, s: h.push(s["number"], "grantPermissions", {"pkg": [PKG["linphone"]]}))
    if _enabled("nextcloud") and st.get("nc_app_password"):
        once("nextcloud_login", PKG["nextcloud"], send_nextcloud_login)
    if _enabled("davx5") and st.get("nc_app_password"):
        once("contacts_login", PKG["davx5"], send_contacts_login)
        once("davx5_perms", PKG["davx5"],
             lambda h, s: h.push(s["number"], "grantPermissions", {"pkg": [PKG["davx5"]]}))


# ---------------------------------------------------------------- per-service account setup
def ensure_traccar(tc: Traccar, dev: dict, st: dict):
    st["traccar_id"] = tc.ensure_device(st["number"], _name(dev))


def user_account(user_name: str, number: str) -> str:
    """A Nextcloud user id of the device's own, derived from the person's name."""
    slug = re.sub(r"[^a-z0-9]+", "-", user_name.lower()).strip("-")
    base = "u-" + (slug or re.sub(r"[^a-z0-9]+", "-", number.lower()).strip("-"))[:50]
    taken = {r["nc_user"] for r in db.q("SELECT nc_user FROM devices WHERE number<>?", (number,))}
    uid, n = base, 2
    while uid in taken:
        uid, n = f"{base}-{n}", n + 1
    return uid


def ensure_nextcloud(nc: Nextcloud, dev: dict, st: dict):
    uid = st.get("nc_user") or "dev-" + re.sub(r"[^a-z0-9_.-]", "", st["number"].lower())
    if not st.get("nc_password") or not nc.user_exists(uid):
        pw = _pw()
        if nc.user_exists(uid):
            nc.set_password(uid, pw)
        else:
            nc.create_user(uid, pw, st.get("user_name") or _name(dev), config.NC_DEVICE_GROUP,
                           st.get("user_email") or "")
        st.update(nc_user=uid, nc_password=pw, nc_app_password=None)
        st["steps"].pop("nextcloud_login", None)
        st["steps"].pop("contacts_login", None)
    if not st.get("nc_app_password"):
        st["nc_app_password"] = nc.app_password(uid, st["nc_password"])


def ensure_sip(pbx: FreePBX | None, dev: dict, st: dict):
    if not st.get("ext"):
        return
    if not st.get("sip_secret") and pbx and config.PBX_MANAGE_SECRETS:
        ext = st["ext"]
        if pbx.has_extension(ext):
            # Never change the password of an existing extension: other devices may be using it
            st["sip_secret"] = pbx.secret(ext)
            if not st["sip_secret"]:
                raise RuntimeError(f"extension {ext} has no readable SIP password")
            db.log("info", f"Using existing extension {ext}", st["number"])
        else:
            secret = _pw(20)
            pbx.add_extension(ext, st.get("user_name") or _name(dev),
                              st.get("user_email") or f"ext{ext}@{config.DOMAIN}", secret)
            st["sip_secret"] = secret
            if config.PBX_RING_GROUP:
                try:
                    pbx.add_to_ring_group(ext, config.PBX_RING_GROUP)
                    db.log("info", f"Added extension {ext} to ring group {config.PBX_RING_GROUP}", st["number"])
                except Exception as e:
                    db.log("error", f"Could not add {ext} to ring group {config.PBX_RING_GROUP}: {e}", st["number"])
            if pbx.reload():
                db.log("info", f"Created extension {ext}", st["number"])
            else:
                db.log("error", f"Created extension {ext}: press Apply Config in FreePBX to activate it", st["number"])
    if st.get("sip_secret") and not st.get("prov_token"):
        st["prov_token"] = secrets.token_urlsafe(32)


def linphone_xml(st: dict, display: str) -> str:
    dom = config.SIP_DOMAIN
    proxy_host = config.SIP_PROXY or dom
    tr = config.SIP_TRANSPORT
    scheme = "sips" if tr == "tls" else "sip"
    proxy = f"<{scheme}:{proxy_host}:{config.SIP_PORT};transport={tr}>"
    ident = f'"{display}" <sip:{st["ext"]}@{dom}>'

    def e(name, value):
        return f'    <entry name="{name}" overwrite="true">{escape(str(value))}</entry>\n'

    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<config xmlns="http://www.linphone.org/xsds/lpconfig.xsd">\n'
            '  <section name="sip">\n' + e("default_proxy", 0) + '  </section>\n'
            '  <section name="proxy_0" overwrite="true">\n'
            + e("reg_proxy", proxy) + e("reg_route", proxy) + e("reg_identity", ident)
            + e("reg_expires", 3600) + e("reg_sendregister", 1) + e("publish", 0)
            + e("dial_escape_plus", 0) + e("quality_reporting_enabled", 0) +
            '  </section>\n'
            '  <section name="auth_info_0" overwrite="true">\n'
            + e("username", st["ext"]) + e("userid", st["ext"]) + e("passwd", st["sip_secret"])
            + e("domain", dom) +
            '  </section>\n'
            '  <section name="app">\n' + e("first_launch", 0) + e("auto_start", 1) + '  </section>\n'
            '</config>\n')


# ---------------------------------------------------------------- directory (shared address book)
def _vcard(uid: str, c: dict) -> str:
    def esc(v):
        return (v or "").replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")

    lines = ["BEGIN:VCARD", "VERSION:3.0", f"UID:{uid}", f"FN:{esc(c['name'])}", f"N:{esc(c['name'])};;;;"]
    if c.get("org"):
        lines.append(f"ORG:{esc(c['org'])}")
    if c.get("title"):
        lines.append(f"TITLE:{esc(c['title'])}")
    if c.get("phone"):
        lines.append(f"TEL;TYPE=WORK,VOICE:{esc(c['phone'])}")
    if c.get("mobile"):
        lines.append(f"TEL;TYPE=CELL:{esc(c['mobile'])}")
    if c.get("sip"):
        sip = c["sip"] if c["sip"].startswith("sip:") else f"sip:{c['sip']}"
        lines.append(f"IMPP;X-SERVICE-TYPE=SIP:{esc(sip)}")
        lines.append(f"X-SIP:{esc(sip[4:])}")
    if c.get("email"):
        lines.append(f"EMAIL;TYPE=WORK:{esc(c['email'])}")
    if c.get("note"):
        lines.append(f"NOTE:{esc(c['note'])}")
    lines.append("CATEGORIES:HBS Directory")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


def directory_entries(pbx_exts: list[dict]) -> dict[str, dict]:
    """filename -> contact dict, from manual contacts + PBX extensions."""
    out = {}
    for r in db.q("SELECT * FROM contacts"):
        c = dict(r)
        out[f"hbs-c{c['id']}.vcf"] = c
    for e in pbx_exts:
        sip = f"{e['ext']}@{config.SIP_DOMAIN}" if config.SIP_DOMAIN else ""
        out[f"hbs-ext{e['ext']}.vcf"] = {"name": e["name"], "phone": e["ext"], "sip": sip, "org": "Extensions"}
    return out


def sync_directory(nc: Nextcloud, pbx_exts: list[dict]):
    if not db.kv_get("dir_book_ready"):  # Nextcloud rate-limits sharing, so only do it once
        nc.ensure_directory_book(config.NC_DEVICE_GROUP)
        db.kv_set("dir_book_ready", True)
    wanted = directory_entries(pbx_exts)
    existing = nc.list_cards()
    cache = db.kv_get("dir_hashes", {})
    changed = 0
    for fn, c in wanted.items():
        card = _vcard(fn[:-4], c)
        h = hashlib.sha1(card.encode()).hexdigest()
        if fn not in existing or cache.get(fn) != h:
            nc.put_card(fn, card)
            cache[fn] = h
            changed += 1
    for fn in existing:
        if fn.startswith("hbs-") and fn not in wanted:
            nc.delete_card(fn)
            cache.pop(fn, None)
            changed += 1
    db.kv_set("dir_hashes", cache)
    if changed:
        db.log("info", f"Directory sync: {changed} contact(s) updated, {len(wanted)} total")


# ---------------------------------------------------------------- permanent removal
def delete_device(st: dict) -> list[str]:
    """Remove a device everywhere. Hold the sync lock: a running sync would otherwise recreate it.

    Headwind goes first: if it refuses, nothing is lost, and once it is gone sync can't bring the
    device back. If a later step fails the bridge row stays, so deleting again retries the rest.
    """
    number = st["number"]
    hw = Headwind()
    for dev in hw.devices():  # by number: hmdm_id may be stale, and the device may already be gone
        if dev.get("number") == number:
            hw.delete_device(dev["id"])

    errors = []
    if st.get("traccar_id") and _enabled("traccar"):
        try:
            Traccar().delete_device(st["traccar_id"])
        except Exception as e:
            errors.append(f"traccar: {e}")

    uid = st.get("nc_user")
    if uid and (_enabled("nextcloud") or _enabled("davx5")):
        # Numbers differing only in case map to the same Nextcloud user
        if db.q("SELECT 1 FROM devices WHERE nc_user=? AND number<>?", (uid, number)):
            db.log("info", f"Kept Nextcloud user {uid}: another device still uses it", number)
        else:
            try:
                Nextcloud().delete_user(uid)
            except Exception as e:
                errors.append(f"nextcloud: {e}")

    if errors:
        st["last_error"] = "Delete incomplete, click Delete to retry: " + "; ".join(errors)
        db.save_device(st)
        db.log("error", st["last_error"], number)
    else:
        db.x("DELETE FROM devices WHERE number=?", (number,))
        db.log("info", "Device permanently deleted", number)
    return errors


# ---------------------------------------------------------------- one-button user link
def link_user(login: str, email: str) -> tuple[str, str]:
    """Link a WalkieFleet account to the extension with the same number, and record the email."""
    user = next((u for u in walkiefleet.users() if u.get("Login") == login), None)
    if not user:
        raise RuntimeError(f"WalkieFleet user {login} not found")
    if not re.fullmatch(r"[0-9]{2,6}", login):
        raise RuntimeError(f"{login} has no matching extension number")
    pbx = FreePBX()
    done = []
    if pbx.has_extension(login):
        # FreePBX emails a welcome message on every update, so only update a changed address
        if not db.q("SELECT 1 FROM linked_users WHERE login=? AND email=?", (login, email)):
            pbx.set_email(login, email)
        done.append(f"extension {login} kept")
    else:
        pbx.add_extension(login, user.get("Name") or login, email, _pw(20))
        if config.PBX_RING_GROUP:
            pbx.add_to_ring_group(login, config.PBX_RING_GROUP)
        done.append(f"extension {login} created")
    if not pbx.reload():
        done.append("press Apply Config in FreePBX")
    if (user.get("SipID") or "").split("@")[0] != login:
        walkiefleet.set_sip_id(login, f"{login}@{config.SIP_DOMAIN}")
        done.append("WalkieFleet updated")
    else:
        done.append("WalkieFleet already linked")
    db.x("INSERT OR REPLACE INTO linked_users(login, name, ext, email, updated) VALUES (?,?,?,?,?)",
         (login, user.get("Name"), login, email, time.time()))
    db.log("info", f"Linked to {login}, {email}: " + ", ".join(done), login)
    return user.get("Name") or login, ", ".join(done)


# ---------------------------------------------------------------- ElevenLabs phone operator
OPERATOR_GREETING = ("שלום, הגעתם להצלה בית שמש. הקישו שלוחה בת שלוש ספרות, או אמרו שם. למצב חירום, הישארו על הקו. "
                     "Hatzala Beit Shemesh. Enter a three digit extension, or say a name. "
                     "For an emergency, stay on the line.")


def operator_prompt(entries: list[dict], group: str) -> str:
    directory = "\n".join(f"- {e['ext']}: {e['name']}" for e in entries)
    return f"""You are the bilingual Hebrew and English telephone operator for Hatzala Beit Shemesh. Start in Hebrew and
continue in the caller's language. Keep every response very short.

Your only job is to connect the caller:
1. If the caller enters or says an extension listed below, transfer to it immediately without asking again.
2. If they say a name, find it in the directory, confirm the one match in a few words, then transfer.
3. If several people match, ask which one. Offer only the matching names.
4. If the extension or name is not listed, say so once and ask again. After a second failure, transfer to {group}.

Transfer to {group} immediately, without asking anything, if the caller:
- mentions an emergency, or anything medical, or sounds distressed
- stays silent or does not respond
- asks for a person, the operator or the main line

Never read out the whole directory. If asked for it, ask for the name they want and confirm matches only.
Never connect a caller to any number that is not listed. Digits may arrive as text from the keypad.
Never request or discuss medical, patient, incident, authentication, or HCAD information. Never give out phone
numbers or personal details.

Directory (extension: name):
{directory}"""


def sync_operator(pbx_exts: list[dict]):
    """Keep the phone operator's directory and transfer list in step with FreePBX."""
    group = config.PBX_RING_GROUP
    entries = sorted((e for e in pbx_exts if e["ext"] not in config.PBX_PRIVATE_EXTS), key=lambda e: e["ext"])
    state = hashlib.sha1(json.dumps([entries, OPERATOR_GREETING, group], sort_keys=True).encode()).hexdigest()
    if db.kv_get("operator_state") == state:
        return

    def rule(ext: str, condition: str) -> dict:
        return {"custom_sip_headers": [], "transfer_type": "sip_refer", "sip_refer_play_dialtone": True,
                "transfer_destination": {"type": "sip_uri", "sip_uri": f"sip:{ext}@{config.SIP_DOMAIN}"},
                "condition": condition}

    transfers = [rule(group, "Emergency, medical or distressed caller, silence, a request for a person, "
                             "or a destination that could not be found.")]
    transfers += [rule(e["ext"], f"Caller wants extension {e['ext']}, {e['name']}.") for e in entries]
    ElevenLabs().update_agent(config.ELEVENLABS_AGENT_ID, {
        "conversation": {"dtmf_input_settings": {"enabled": True, "dtmf_input_timeout": 2.5, "hash_terminator": True,
                                                 "redact_input": False}},
        "agent": {"first_message": OPERATOR_GREETING, "prompt": {
            "prompt": operator_prompt(entries, group),
            "built_in_tools": {"transfer_to_number": {
                "type": "system", "name": "transfer_to_number",
                "description": "Connect the caller to a listed extension or the ring group.",
                "params": {"system_tool_type": "transfer_to_number", "transfers": transfers,
                           "enable_client_message": True}}}}}})
    db.kv_set("operator_state", state)
    db.log("info", f"Phone operator updated: {len(entries)} extensions")


# ---------------------------------------------------------------- main loop
def sync_all(force_apps=False):
    hw = Headwind()
    last_apps = db.kv_get("apps_bootstrap_ts", 0)
    app_ids = db.kv_get("app_ids", {})
    incomplete = len(app_ids) < len(config.ENABLED_APPS)
    if force_apps or incomplete or time.time() - last_apps > 86400:
        app_ids = {**app_ids, **apps.register_all(hw)}
        db.kv_set("app_ids", app_ids)
        db.kv_set("apps_bootstrap_ts", time.time())

    tc = Traccar() if _enabled("traccar") else None
    nc = Nextcloud() if (_enabled("nextcloud") or _enabled("davx5")) else None
    pbx = FreePBX() if (config.PBX_ENABLED and config.PBX_URL) else None
    pbx_exts = []
    if pbx:
        try:
            pbx_exts = pbx.extensions()
        except Exception as e:
            db.log("error", f"FreePBX: {e}")

    if nc:
        try:
            nc.ensure_group(config.NC_DEVICE_GROUP)
        except Exception as e:
            db.log("error", f"Nextcloud: {e}")

    devices = hw.devices()
    for dev in devices:
        number = dev["number"]
        st = db.device(number) or {"number": number, "steps": {}}
        st.update(hmdm_id=dev["id"], description=dev.get("description"))
        errors = []
        for label, fn, client in (("traccar", ensure_traccar, tc), ("nextcloud", ensure_nextcloud, nc)):
            if client:
                try:
                    fn(client, dev, st)
                except Exception as e:
                    errors.append(f"{label}: {e}")
        if _enabled("linphone"):
            try:
                ensure_sip(pbx, dev, st)
            except Exception as e:
                errors.append(f"sip: {e}")
        try:
            apply_managed_configs(hw, dev, st, app_ids)
            run_one_time_steps(hw, dev, st)
        except Exception as e:
            errors.append(f"headwind: {e}")
        st["last_error"] = "; ".join(errors) or None
        if errors:
            db.log("error", st["last_error"], number)
        db.save_device(st)

    if nc:
        try:
            sync_directory(nc, pbx_exts)
        except Exception as e:
            db.log("error", f"Directory sync: {e}")
    if pbx_exts and config.ELEVENLABS_AGENT_ID and config.PBX_RING_GROUP:
        try:
            sync_operator(pbx_exts)
        except Exception as e:
            db.log("error", f"Phone operator: {e}")
    db.kv_set("last_sync", time.time())
    return len(devices)
