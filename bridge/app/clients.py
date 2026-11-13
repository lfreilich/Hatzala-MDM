"""API clients: Headwind MDM, Traccar, Nextcloud (OCS + CardDAV), FreePBX (GraphQL)."""
import hashlib
import json
import subprocess
import time
import uuid
from xml.etree import ElementTree as ET

import httpx

from . import config

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class ApiError(RuntimeError):
    pass


# ============================================================================ Headwind MDM
class Headwind:
    """Talks to Tomcat directly (127.0.0.1:8080) using the JWT API."""

    def __init__(self, base=None, login=None, password=None):
        self.base = (base or config.HMDM_URL).rstrip("/")
        self.login_name = login or config.HMDM_LOGIN
        self.password = password or config.HMDM_PASSWORD
        self.token = None
        self.token_ts = 0.0
        self.http = httpx.Client(timeout=TIMEOUT)

    def _login(self):
        md5 = hashlib.md5(self.password.encode()).hexdigest().upper()
        r = self.http.post(f"{self.base}/rest/public/jwt/login",
                           json={"login": self.login_name, "password": md5})
        if r.status_code != 200:
            raise ApiError(f"Headwind login failed ({r.status_code}). Check HMDM_LOGIN/HMDM_PASSWORD.")
        self.token = r.json()["id_token"]
        self.token_ts = time.time()

    def _req(self, method, path, **kw):
        if not self.token or time.time() - self.token_ts > 3000:
            self._login()
        for attempt in (1, 2):
            r = self.http.request(method, f"{self.base}/rest{path}",
                                  headers={"Authorization": f"Bearer {self.token}"}, **kw)
            if r.status_code in (401, 403) and attempt == 1:
                self._login()
                continue
            break
        if r.status_code >= 400:
            raise ApiError(f"Headwind {method} {path} -> HTTP {r.status_code}: {r.text[:300]}")
        if not r.content:
            return None
        body = r.json()
        if isinstance(body, dict) and "status" in body:
            if body.get("status") != "OK":
                raise ApiError(f"Headwind {method} {path} -> {body.get('status')}: {body.get('message')}")
            return body.get("data")
        return body

    # -- devices
    def devices(self) -> list[dict]:
        out, page = [], 1
        while True:
            data = self._req("POST", "/private/devices/search", json={"pageSize": 200, "pageNum": page})
            items = (data or {}).get("devices", {}).get("items", [])
            out.extend(items)
            total = (data or {}).get("devices", {}).get("totalItemsCount", len(out))
            if len(out) >= total or not items:
                return out
            page += 1

    def create_device(self, number: str, description: str, config_id: int, custom1: str = ""):
        """custom1 holds the WalkieFleet login: the agent writes it into wfinit.cfg in place of the word CUSTOM1."""
        body = {"number": number, "description": description, "configurationId": config_id}
        if custom1:
            body["custom1"] = custom1
        return self._req("PUT", "/private/devices", json=body)

    def delete_device(self, device_id: int):
        self._req("DELETE", f"/private/devices/{device_id}")

    def device_app_settings(self, device_id: int) -> list[dict]:
        return self._req("GET", f"/private/devices/{device_id}/applicationSettings") or []

    def save_device_app_settings(self, device_id: int, settings: list[dict]):
        self._req("POST", f"/private/devices/{device_id}/applicationSettings", json=settings)
        self._req("POST", f"/private/devices/{device_id}/applicationSettings/notify")

    # -- push
    def push(self, device_number: str, message_type: str, payload: dict | None = None):
        body = {"scope": "device", "deviceNumber": device_number, "messageType": message_type}
        if payload is not None:
            body["payload"] = json.dumps(payload)
        self._req("POST", "/private/plugin-push/send", json=body)

    # -- configurations & applications
    def configurations(self) -> list[dict]:
        return self._req("GET", "/private/configurations/search") or []

    def applications(self) -> list[dict]:
        return self._req("GET", "/private/applications/search") or []

    def app_versions(self, app_id: int) -> list[dict]:
        return self._req("GET", f"/private/applications/{app_id}/versions") or []

    def create_app(self, name, pkg, version, version_code, url) -> dict:
        return self._req("PUT", "/private/applications/android", json={
            "name": name, "pkg": pkg, "version": version, "versionCode": version_code,
            "url": url, "type": "app", "showIcon": True, "system": False,
            "runAfterInstall": False, "runAtBoot": False,
        })

    def add_app_version(self, app_id: int, version, version_code, url):
        self._req("PUT", "/private/applications/versions", json={
            "applicationId": app_id, "version": version, "versionCode": version_code, "url": url,
        })

    def upgrade_config_app(self, config_id: int, app_id: int):
        """Point the configuration at the app's newest version (Headwind's own 'Upgrade' button)."""
        self._req("PUT", "/private/configurations/application/upgrade",
                  json={"configurationId": config_id, "applicationId": app_id})

    def app_configurations(self, app_id: int) -> list[dict]:
        return self._req("GET", f"/private/applications/configurations/{app_id}") or []

    def link_app(self, app_id: int, config_ids: list[int], show_icon=True):
        links = [{"applicationId": app_id, "configurationId": cid, "action": 1,
                  "showIcon": show_icon, "notify": True} for cid in config_ids]
        self._req("POST", "/private/applications/configurations",
                  json={"applicationId": app_id, "configurations": links})


# ============================================================================ Traccar
class Traccar:
    def __init__(self):
        self.base = config.TRACCAR_URL
        self.http = httpx.Client(timeout=TIMEOUT, auth=(config.TRACCAR_ADMIN_EMAIL, config.TRACCAR_ADMIN_PASSWORD))

    def devices(self) -> list[dict]:
        r = self.http.get(f"{self.base}/api/devices", params={"all": "true"})
        r.raise_for_status()
        return r.json()

    def ensure_device(self, unique_id: str, name: str) -> int:
        for d in self.devices():
            if d.get("uniqueId") == unique_id:
                if d.get("name") != name:
                    d["name"] = name
                    self.http.put(f"{self.base}/api/devices/{d['id']}", json=d).raise_for_status()
                return d["id"]
        r = self.http.post(f"{self.base}/api/devices", json={"name": name, "uniqueId": unique_id})
        r.raise_for_status()
        return r.json()["id"]

    def delete_device(self, device_id: int):
        r = self.http.delete(f"{self.base}/api/devices/{device_id}")
        if r.status_code != 404:  # already gone is fine
            r.raise_for_status()

    def positions(self) -> dict[int, dict]:
        r = self.http.get(f"{self.base}/api/positions")
        r.raise_for_status()
        return {p["deviceId"]: p for p in r.json()}


# ============================================================================ Nextcloud
OCS = {"OCS-APIRequest": "true", "Accept": "application/json"}
DAV_NS = {"d": "DAV:"}


class Nextcloud:
    def __init__(self):
        self.base = config.NC_URL
        # Talk to the container directly but present the public host name (trusted_domains)
        self.headers = {"Host": config.NC_HOST, "X-Forwarded-Proto": "https"}
        self.http = httpx.Client(timeout=TIMEOUT, headers=self.headers,
                                 auth=(config.NC_ADMIN_USER, config.NC_ADMIN_PASSWORD))

    def _ocs(self, method, path, **kw):
        r = self.http.request(method, f"{self.base}/ocs/v1.php{path}", headers=OCS, **kw)
        r.raise_for_status()
        meta = r.json()["ocs"]["meta"]
        return meta, r.json()["ocs"].get("data")

    def ensure_group(self, gid: str):
        meta, _ = self._ocs("POST", "/cloud/groups", data={"groupid": gid})
        if meta["statuscode"] not in (100, 102):  # 102 = exists
            raise ApiError(f"Nextcloud group create: {meta}")

    def user_exists(self, uid: str) -> bool:
        meta, _ = self._ocs("GET", f"/cloud/users/{uid}")
        return meta["statuscode"] == 100

    def create_user(self, uid: str, password: str, display: str, group: str, email: str = ""):
        meta, _ = self._ocs("POST", "/cloud/users",
                            data={"userid": uid, "password": password, "displayName": display, "groups[]": group,
                                  "email": email})
        if meta["statuscode"] not in (100, 102):
            raise ApiError(f"Nextcloud user create {uid}: {meta.get('message')}")

    def delete_user(self, uid: str):
        if not self.user_exists(uid):
            return
        meta, _ = self._ocs("DELETE", f"/cloud/users/{uid}")
        if meta["statuscode"] != 100:
            raise ApiError(f"Nextcloud user delete {uid}: {meta.get('message')}")

    def set_password(self, uid: str, password: str):
        meta, _ = self._ocs("PUT", f"/cloud/users/{uid}", data={"key": "password", "value": password})
        if meta["statuscode"] != 100:
            raise ApiError(f"Nextcloud set password {uid}: {meta.get('message')}")

    def app_password(self, uid: str, password: str) -> str:
        r = httpx.get(f"{self.base}/ocs/v2.php/core/getapppassword", headers={**self.headers, **OCS},
                      auth=(uid, password), timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()["ocs"]["data"]["apppassword"]

    # -- CardDAV shared directory
    def _book_url(self):
        return f"{self.base}/remote.php/dav/addressbooks/users/{config.NC_ADMIN_USER}/{config.NC_DIRECTORY_BOOK}/"

    def ensure_directory_book(self, share_group: str):
        url = self._book_url()
        r = self.http.request("PROPFIND", url, headers={"Depth": "0"})
        if r.status_code == 404:
            body = ('<d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:set><d:prop>'
                    '<d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>'
                    f'<d:displayname>{config.NC_DIRECTORY_NAME}</d:displayname></d:prop></d:set></d:mkcol>')
            r = self.http.request("MKCOL", url, content=body, headers={"Content-Type": "application/xml"})
            if r.status_code not in (201, 405):
                raise ApiError(f"MKCOL address book -> {r.status_code} {r.text[:200]}")
        share = ('<o:share xmlns:d="DAV:" xmlns:o="http://owncloud.org/ns"><o:set>'
                 f'<d:href>principal:principals/groups/{share_group}</d:href></o:set></o:share>')
        r = self.http.post(url, content=share, headers={"Content-Type": "application/xml"})
        if r.status_code >= 400:
            raise ApiError(f"Share address book -> {r.status_code} {r.text[:200]}")

    def list_cards(self) -> dict[str, str]:
        """href -> etag for our managed cards."""
        r = self.http.request("PROPFIND", self._book_url(), headers={"Depth": "1"},
                              content='<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>')
        r.raise_for_status()
        out = {}
        for resp in ET.fromstring(r.content).findall("d:response", DAV_NS):
            href = resp.findtext("d:href", namespaces=DAV_NS) or ""
            if href.endswith(".vcf"):
                out[href.rsplit("/", 1)[-1]] = resp.findtext(".//d:getetag", namespaces=DAV_NS) or ""
        return out

    def put_card(self, filename: str, vcard: str):
        r = self.http.put(self._book_url() + filename, content=vcard.encode(),
                          headers={"Content-Type": "text/vcard; charset=utf-8"})
        if r.status_code >= 400:
            raise ApiError(f"PUT {filename} -> {r.status_code}")

    def delete_card(self, filename: str):
        self.http.delete(self._book_url() + filename)


# ============================================================================ ElevenLabs
class ElevenLabs:
    def __init__(self):
        self.http = httpx.Client(timeout=TIMEOUT, base_url="https://api.elevenlabs.io",
                                 headers={"xi-api-key": config.ELEVENLABS_API_KEY})

    def update_agent(self, agent_id: str, conversation_config: dict):
        r = self.http.patch(f"/v1/convai/agents/{agent_id}", json={"conversation_config": conversation_config})
        if r.status_code >= 400:
            raise ApiError(f"ElevenLabs agent update -> {r.status_code}: {r.text[:300]}")


# ============================================================================ FreePBX
class FreePBX:
    def __init__(self):
        self.base = config.PBX_URL
        self.http = httpx.Client(timeout=TIMEOUT)
        self.token = None
        self.token_exp = 0.0

    def _auth(self):
        if self.token and time.time() < self.token_exp - 60:
            return
        r = self.http.post(f"{self.base}/admin/api/api/token", data={
            "grant_type": "client_credentials", "client_id": config.PBX_CLIENT_ID,
            "client_secret": config.PBX_CLIENT_SECRET, "scope": config.PBX_SCOPE})
        if r.status_code != 200:
            raise ApiError(f"FreePBX token -> {r.status_code} {r.text[:200]}")
        j = r.json()
        self.token = j["access_token"]
        self.token_exp = time.time() + int(j.get("expires_in", 3600))

    def gql(self, query: str, variables: dict | None = None) -> dict:
        self._auth()
        r = self.http.post(f"{self.base}/admin/api/api/gql", json={"query": query, "variables": variables or {}},
                           headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()
        j = r.json()
        if j.get("errors"):
            raise ApiError(f"FreePBX GraphQL: {j['errors'][0].get('message')}")
        return j["data"]

    def extensions(self) -> list[dict]:
        d = self.gql("query { fetchAllExtensions { status extension { extensionId user { name } } } }")
        out = [{"ext": e["extensionId"], "name": (e.get("user") or {}).get("name") or e["extensionId"]}
               for e in (d["fetchAllExtensions"].get("extension") or [])]
        ids = {e["ext"] for e in out}
        # 99NNN is the WebRTC device of unit NNN, not a number of its own
        return [e for e in out if not (e["ext"].startswith("99") and e["ext"][2:] in ids)]

    def has_extension(self, ext: str) -> bool:
        return ext in {e["ext"] for e in self.extensions()}

    def secret(self, ext: str) -> str:
        d = self.gql("query($e: ID!) { fetchExtension(extensionId: $e) { user { extPassword } } }", {"e": ext})
        return ((d.get("fetchExtension") or {}).get("user") or {}).get("extPassword") or ""

    def add_extension(self, ext: str, name: str, email: str, secret: str):
        d = self.gql("mutation($i: addExtensionInput!) { addExtension(input: $i) { status message } }",
                     {"i": {"extensionId": ext, "name": name, "email": email, "tech": "pjsip",
                            "vmEnable": False, "umEnable": False}})
        if not d["addExtension"].get("status"):
            raise ApiError(f"addExtension {ext}: {d['addExtension'].get('message')}")
        # addExtension can't set a password, and updateExtension needs the email or it silently does nothing
        d = self.gql("mutation($i: updateExtensionInput!) { updateExtension(input: $i) { status message } }",
                     {"i": {"extensionId": ext, "name": name, "email": email, "extPassword": secret}})
        if not d["updateExtension"].get("status"):
            raise ApiError(f"updateExtension {ext}: {d['updateExtension'].get('message')}")

    def set_email(self, ext: str, email: str):
        """Change only the email. updateExtension replaces a password it isn't given, so always send the current one."""
        d = self.gql("query($e: ID!) { fetchExtension(extensionId: $e) { user { name extPassword } } }", {"e": ext})
        user = (d.get("fetchExtension") or {}).get("user") or {}
        if not user.get("extPassword"):
            raise ApiError(f"extension {ext} has no readable password, not updating it")
        d = self.gql("mutation($i: updateExtensionInput!) { updateExtension(input: $i) { status message } }",
                     {"i": {"extensionId": ext, "name": user.get("name") or ext, "email": email,
                            "extPassword": user["extPassword"]}})
        if not d["updateExtension"].get("status"):
            raise ApiError(f"updateExtension {ext}: {d['updateExtension'].get('message')}")
        if self.secret(ext) != user["extPassword"]:
            raise ApiError(f"extension {ext} password changed during the email update")

    def add_to_ring_group(self, ext: str, group: str):
        d = self.gql(f'query {{ fetchRingGroup(groupNumber: "{int(group)}") {{ status groupList }} }}')
        members = [m for m in (d["fetchRingGroup"].get("groupList") or "").split("-") if m]
        if ext in members:
            return
        d = self.gql("mutation($i: updateRingGroupInput!) { updateRingGroup(input: $i) { status message } }",
                     {"i": {"groupNumber": group, "extensionList": "-".join(members + [ext])}})
        if not d["updateRingGroup"].get("status"):
            raise ApiError(f"updateRingGroup {group}: {d['updateRingGroup'].get('message')}")

    def reload(self) -> bool:
        """Apply Config over SSH. False if SSH isn't set up or the reload failed."""
        if not config.PBX_SSH:
            return False
        r = subprocess.run(["ssh", "-i", config.PBX_SSH_KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                            "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/data/pbx_known_hosts",
                            config.PBX_SSH, "fwconsole reload"], capture_output=True, text=True, timeout=120)
        return r.returncode == 0


def new_uid() -> str:
    return uuid.uuid4().hex
