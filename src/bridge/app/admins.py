"""Admin users: one Google account each, with their own Headwind, Traccar and Nextcloud logins behind it.

Adding an admin creates (or takes over) an account in each app with a random password that nobody has
to know, stores it in sso_accounts so /hbs-sso signs them straight in, and only then adds the Google
email to the gate list. Phone users are not admins: they are set up under Link user and never pass the gate.

Where the bridge cannot set an app's password (Headwind won't let its Admin role change a Super-Admin),
an admin types that account's existing password once on the Admins page; it is checked and stored.

Approval: an admin who is not an owner can only propose someone. The request is stored with no accounts
and no gate access until an owner (config.ADMIN_OWNERS, set in .env) approves it. Only owners approve,
reject, remove admins or reset someone else's sign-in. Owners can't be removed from the web.

The service accounts the bridge itself logs in with are never changed or deleted here.
"""
import hashlib
import re
import secrets
import threading
import time

import httpx

from . import config, db, sso
from .clients import ApiError, Headwind, Nextcloud, TIMEOUT

APPS = ("headwind", "traccar", "nextcloud")
LABELS = {"headwind": "Headwind", "traccar": "Map", "nextcloud": "Nextcloud"}
VERIFY = {"headwind": sso._headwind, "traccar": sso._traccar, "nextcloud": sso._nextcloud}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_gate_lock = threading.Lock()


# ------------------------------------------------------------------ gate list (oauth2-proxy reloads it on change)
def gate_emails() -> list[str]:
    try:
        with open(config.GATE_EMAILS_FILE) as f:
            return [ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        return []


def _write_gate(emails: list[str]):
    """Rewrite in place: the file is a single-file bind mount, so a rename would detach it from the gate."""
    seen = list(dict.fromkeys(e.lower() for e in emails))
    with open(config.GATE_EMAILS_FILE, "r+") as f:
        f.seek(0)
        f.write("".join(e + "\n" for e in seen))
        f.truncate()


def _gate_add(email: str):
    with _gate_lock:
        _write_gate(gate_emails() + [email])


def _gate_remove(email: str):
    with _gate_lock:
        _write_gate([e for e in gate_emails() if e != email])


# ------------------------------------------------------------------ helpers
def _password() -> str:
    return secrets.token_urlsafe(18)


def _save(email: str, app: str, login: str, password: str):
    db.x("INSERT OR REPLACE INTO sso_accounts (email, app, login, password) VALUES (?,?,?,?)",
         (email, app, login, password))


def _traccar_http() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, auth=(config.TRACCAR_ADMIN_EMAIL, config.TRACCAR_ADMIN_PASSWORD))


def _hw_users(hw: Headwind) -> list[dict]:
    return hw._req("GET", "/private/users/all", params={"filter": ""}) or []


def _hw_find(hw: Headwind, email: str, login: str = "") -> dict | None:
    for u in _hw_users(hw):
        keys = {k.lower() for k in (email, login) if k}
        if (u.get("email") or "").lower() in keys or u["login"].lower() in keys:
            return u
    return None


def _nc_find(nc: Nextcloud, email: str) -> str | None:
    meta, data = nc._ocs("GET", "/cloud/users", params={"search": email})
    for uid in (data or {}).get("users", []):
        if uid.lower() == email:
            return uid
    return None


# ------------------------------------------------------------------ per-app account setup
def _headwind(email: str, name: str) -> str:
    hw = Headwind()
    pw = _password()
    md5 = hashlib.md5(pw.encode()).hexdigest().upper()
    u = _hw_find(hw, email)
    if u and u["login"] == config.HMDM_LOGIN:
        raise ApiError(f"'{u['login']}' is the bridge's own Headwind login; it can't be given to a person.")
    if u:
        if not (u.get("allDevicesAvailable") and u.get("allConfigAvailable")):
            raise ApiError(f"Headwind user {u['login']} is limited to some devices; give it all devices "
                           "in Headwind first, or enter its existing password.")
        body = dict(u, newPassword=md5, confirmModal=md5, confirm="")
        try:
            hw._req("PUT", "/private/users", json=body)
        except ApiError as e:
            raise ApiError(f"Headwind won't let the bridge change {u['login']}'s password "
                           f"({u['userRole']['name']}): enter its existing password instead. [{str(e)[-60:]}]")
        login, verb = u["login"], "password reset"
    else:
        login = email if len(email) <= 30 else email.split("@")[0][:30]
        if _hw_find(hw, "", login):
            raise ApiError(f"Headwind login '{login}' is already taken by someone else.")
        hw._req("PUT", "/private/users", json={
            "name": name[:50], "email": email, "login": login, "userRole": {"id": 2},  # Admin
            "allConfigAvailable": True, "allDevicesAvailable": True, "configurations": [], "groups": [],
            "confirm": "", "newPassword": md5, "confirmModal": md5, "alertLevel": 0})
        verb = "created (Admin)"
    sso._headwind(login, pw)
    _save(email, "headwind", login, pw)
    return verb


def _traccar(email: str, name: str) -> str:
    if email == config.TRACCAR_ADMIN_EMAIL.lower():  # the bridge's own Traccar login: reuse, never change
        sso._traccar(config.TRACCAR_ADMIN_EMAIL, config.TRACCAR_ADMIN_PASSWORD)
        _save(email, "traccar", config.TRACCAR_ADMIN_EMAIL, config.TRACCAR_ADMIN_PASSWORD)
        return "linked"
    t = _traccar_http()
    r = t.get(f"{config.TRACCAR_URL}/api/users")
    r.raise_for_status()
    u = next((x for x in r.json() if (x.get("email") or "").lower() == email), None)
    pw = _password()
    if u:
        r = t.put(f"{config.TRACCAR_URL}/api/users/{u['id']}",
                  json=dict(u, password=pw, administrator=True, disabled=False))
        verb = "password reset"
    else:
        r = t.post(f"{config.TRACCAR_URL}/api/users",
                   json={"name": name, "email": email, "password": pw, "administrator": True})
        verb = "created (admin)"
    if r.status_code >= 400:
        raise ApiError(f"Traccar -> {r.status_code}: {r.text[:150]}")
    login = u["email"] if u else email
    sso._traccar(login, pw)
    _save(email, "traccar", login, pw)
    return verb


def _nextcloud(email: str, name: str) -> str:
    nc = Nextcloud()
    uid = _nc_find(nc, email)
    if uid and uid == config.NC_ADMIN_USER:
        raise ApiError("That is the bridge's own Nextcloud login.")
    pw = _password()
    if uid:
        nc.set_password(uid, pw)
        nc._ocs("PUT", f"/cloud/users/{uid}/enable")
        verb = "password reset"
    else:
        uid = re.sub(r"[^A-Za-z0-9_.@' -]", "_", email)
        nc.create_user(uid, pw, name, "admin", email)
        verb = "created (admin)"
    meta, _ = nc._ocs("POST", f"/cloud/users/{uid}/groups", data={"groupid": "admin"})
    if meta["statuscode"] not in (100, 102):
        raise ApiError(f"Nextcloud admin group: {meta.get('message')}")
    sso._nextcloud(uid, pw)
    _save(email, "nextcloud", uid, pw)
    return verb


SETUP = {"headwind": _headwind, "traccar": _traccar, "nextcloud": _nextcloud}


# ------------------------------------------------------------------ public actions
def accounts() -> list[dict]:
    """Everyone on the gate list, with which apps sign them in automatically."""
    rows = {}
    for r in db.q("SELECT email, app, login FROM sso_accounts"):
        rows.setdefault(r["email"], {})[r["app"]] = r["login"]
    return [{"email": e, "apps": rows.get(e, {}), "owner": is_owner(e)} for e in gate_emails()]


def setup(email: str, name: str = "", apps=APPS) -> dict[str, tuple[bool, str]]:
    """Create or repair this person's accounts in the given apps; each app's outcome is reported separately."""
    email = email.strip().lower()
    name = (name.strip() or email.split("@")[0])[:50]
    out = {}
    for app in apps:
        try:
            out[app] = (True, SETUP[app](email, name))
        except Exception as e:
            out[app] = (False, str(e)[:220])
            db.log("error", f"Admin setup {LABELS[app]} for {email}: {e}")
    return out


def is_owner(email: str) -> bool:
    return (email or "").strip().lower() in config.ADMIN_OWNERS


def require_owner(actor: str, what: str):
    if not is_owner(actor):
        raise ApiError(f"Only an owner can {what}.")


def require_self_or_owner(actor: str, email: str):
    if (actor or "").strip().lower() != email.strip().lower() and not is_owner(actor):
        raise ApiError("Only an owner can change someone else's sign-in.")


def pending() -> list[dict]:
    return [dict(r) for r in db.q("SELECT * FROM admin_requests ORDER BY requested")]


def _check_new(email: str):
    if not EMAIL.match(email) or len(email) > 50:
        raise ApiError("Enter the person's Google email (50 characters at most).")
    if email in gate_emails():
        raise ApiError(f"{email} is already an admin. Use Repair to fix their sign-in.")


def request(email: str, name: str, actor: str) -> str:
    """Owners add straight away (their adding is the approval). Anyone else files a request."""
    email = email.strip().lower()
    _check_new(email)
    if is_owner(actor):
        return "added"
    if db.q("SELECT 1 FROM admin_requests WHERE email=?", (email,)):
        raise ApiError(f"{email} is already waiting for an owner's approval.")
    db.x("INSERT INTO admin_requests (email, name, requested_by, requested) VALUES (?,?,?,?)",
         (email, name.strip()[:50], (actor or "").lower(), time.time()))
    db.log("info", f"Admin requested: {email} (by {actor or 'unknown'}), waiting for an owner")
    return "pending"


def approve(email: str, actor: str) -> dict[str, tuple[bool, str]]:
    require_owner(actor, "approve admins")
    email = email.strip().lower()
    rows = db.q("SELECT * FROM admin_requests WHERE email=?", (email,))
    if not rows:
        raise ApiError(f"No pending request for {email}.")
    res = add(email, rows[0]["name"] or "", actor, approved_note=f"requested by {rows[0]['requested_by']}")
    db.x("DELETE FROM admin_requests WHERE email=?", (email,))
    return res


def reject(email: str, actor: str):
    """Owners reject; whoever asked can withdraw their own request."""
    email = email.strip().lower()
    rows = db.q("SELECT requested_by FROM admin_requests WHERE email=?", (email,))
    if not rows:
        raise ApiError(f"No pending request for {email}.")
    if not is_owner(actor) and rows[0]["requested_by"] != (actor or "").lower():
        raise ApiError("Only an owner, or whoever asked, can cancel this request.")
    db.x("DELETE FROM admin_requests WHERE email=?", (email,))
    db.log("info", f"Admin request for {email} rejected (by {actor or 'unknown'})")


def add(email: str, name: str, actor: str, approved_note: str = "") -> dict[str, tuple[bool, str]]:
    """Create the accounts and open the gate. Owners only: reached by an owner adding or approving."""
    require_owner(actor, "add admins")
    email = email.strip().lower()
    _check_new(email)
    res = setup(email, name, ("headwind",))
    if not res["headwind"][0]:
        raise ApiError(f"Not added: {res['headwind'][1]}")
    res.update(setup(email, name, ("traccar", "nextcloud")))
    _gate_add(email)
    db.x("DELETE FROM admin_requests WHERE email=?", (email,))
    db.log("info", f"Admin added: {email} (approved by {actor}{', ' + approved_note if approved_note else ''})")
    return res


def link_existing(email: str, app: str, login: str, password: str, actor: str):
    """Store an account whose password the bridge can't set. Checked by signing in first."""
    email = email.strip().lower()
    require_self_or_owner(actor, email)
    if app not in APPS or email not in gate_emails():
        raise ApiError("Unknown admin or app.")
    VERIFY[app](login.strip(), password)
    _save(email, app, login.strip(), password)
    db.log("info", f"Admin {email}: existing {LABELS[app]} login {login.strip()} stored")


def remove(email: str, actor: str) -> list[str]:
    """Out of the gate first (takes effect on their next request), then their app accounts go."""
    require_owner(actor, "remove admins")
    email = email.strip().lower()
    if email == (actor or "").lower():
        raise ApiError("You can't remove yourself.")
    if is_owner(email):
        raise ApiError(f"{email} is an owner. Owners are changed in the server's .env file, not here.")
    if email not in gate_emails():
        raise ApiError(f"{email} is not an admin.")
    if len(gate_emails()) <= 1:
        raise ApiError("Can't remove the last admin.")
    _gate_remove(email)
    notes = []
    logins = {r["app"]: r["login"] for r in db.q("SELECT app, login FROM sso_accounts WHERE email=?", (email,))}
    try:
        hw = Headwind()
        u = _hw_find(hw, email, logins.get("headwind", ""))
        if u and u["login"] != config.HMDM_LOGIN:
            hw._req("DELETE", f"/private/users/other/{u['id']}")
            notes.append("Headwind user deleted")
    except Exception as e:
        notes.append(f"Headwind: {str(e)[:120]}")
    try:
        if email != config.TRACCAR_ADMIN_EMAIL.lower():
            t = _traccar_http()
            u = next((x for x in t.get(f"{config.TRACCAR_URL}/api/users").json()
                      if (x.get("email") or "").lower() == email), None)
            if u:
                t.delete(f"{config.TRACCAR_URL}/api/users/{u['id']}").raise_for_status()
                notes.append("Map user deleted")
    except Exception as e:
        notes.append(f"Map: {str(e)[:120]}")
    try:
        nc = Nextcloud()
        uid = _nc_find(nc, email)
        if uid and uid != config.NC_ADMIN_USER:
            nc._ocs("PUT", f"/cloud/users/{uid}/disable")
            notes.append("Nextcloud user disabled (files kept)")
    except Exception as e:
        notes.append(f"Nextcloud: {str(e)[:120]}")
    db.x("DELETE FROM sso_accounts WHERE email=?", (email,))
    db.log("info", f"Admin removed: {email} (by {actor or 'unknown'}): {'; '.join(notes)}")
    return notes
