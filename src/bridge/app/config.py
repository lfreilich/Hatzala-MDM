"""Bridge configuration, read from environment (/opt/hbs-addons/stack/.env)."""
import os


def _secret(name: str, default: str = "") -> str:
    """Value from NAME, or from the file named in NAME_FILE (used for passwords with special characters)."""
    path = os.getenv(f"{name}_FILE")
    if path and os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return os.getenv(name, default)


def _b(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "y", "on")


DOMAIN = os.getenv("DOMAIN", "hatzala-mdm.com")
PUBLIC_IP = os.getenv("PUBLIC_IP", "72.62.58.146")  # by-address enrollment, for networks whose DNS hides DOMAIN
OPS_HOST = os.getenv("OPS_HOST", f"ops.{DOMAIN}")
TRACK_HOST = os.getenv("TRACK_HOST", f"track.{DOMAIN}")
MAP_HOST = os.getenv("MAP_HOST", f"map.{DOMAIN}")
NC_HOST = os.getenv("NC_HOST", f"cloud.{DOMAIN}")
DNS_HOST = os.getenv("DNS_HOST", f"dns.{DOMAIN}")
RUSTDESK_HOST = os.getenv("RUSTDESK_HOST", f"rd.{DOMAIN}")

DATA_DIR = os.getenv("BRIDGE_DATA", "/data")
APK_DIR = os.path.join(DATA_DIR, "apk")
DB_PATH = os.path.join(DATA_DIR, "bridge.sqlite3")
# Owners approve new admins and remove admins. Set only in .env, so nobody can make themselves an owner from the web.
ADMIN_OWNERS = {e.strip().lower() for e in os.getenv("ADMIN_OWNERS", "").split(",") if e.strip()}
GATE_EMAILS_FILE = os.getenv("GATE_EMAILS_FILE", "/gate/allowed-emails.txt")  # Google accounts allowed past the gate
BIND_PORT = int(os.getenv("BRIDGE_PORT", "8090"))
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "300"))

# Headwind MDM (reached directly on Tomcat, bypassing the 2FA edge)
HMDM_URL = os.getenv("HMDM_INTERNAL_URL", "http://127.0.0.1:8080").rstrip("/")
HMDM_LOGIN = os.getenv("HMDM_LOGIN", "admin")
HMDM_PASSWORD = _secret("HMDM_PASSWORD")
# Configurations the add-on apps get attached to ("all" or comma separated ids)
HMDM_CONFIG_IDS = os.getenv("HMDM_CONFIG_IDS", "all")

# Traccar
TRACCAR_URL = os.getenv("TRACCAR_URL", "http://127.0.0.1:8082").rstrip("/")
TRACCAR_ADMIN_EMAIL = os.getenv("TRACCAR_ADMIN_EMAIL", "")
TRACCAR_ADMIN_PASSWORD = _secret("TRACCAR_ADMIN_PASSWORD")
TRACKING_INTERVAL = int(os.getenv("TRACKING_INTERVAL", "60"))  # seconds between fixes while a session runs
# Tracking is on demand only: "Start tracking" runs a session this long, then the app is stopped
TRACK_SESSION_MINUTES = int(os.getenv("TRACK_SESSION_MINUTES", "10"))
PCR_PKG = os.getenv("PCR_PKG", "org.hatzbs.pcr")  # in-house PCR app; gets the HCAD email as login_hint

# Nextcloud
NC_URL = os.getenv("NC_URL", "http://127.0.0.1:8083").rstrip("/")
NC_ADMIN_USER = os.getenv("NC_ADMIN_USER", "admin")
NC_ADMIN_PASSWORD = _secret("NC_ADMIN_PASSWORD")
NC_DEVICE_GROUP = os.getenv("NC_DEVICE_GROUP", "devices")
NC_DIRECTORY_BOOK = os.getenv("NC_DIRECTORY_BOOK", "hbs-directory")
NC_DIRECTORY_NAME = os.getenv("NC_DIRECTORY_NAME", "HBS Directory")

# RustDesk
RUSTDESK_KEY_FILE = os.getenv("RUSTDESK_KEY_FILE", "/rustdesk/id_ed25519.pub")

# FreePBX / SIP
PBX_ENABLED = _b("PBX_ENABLED")
PBX_URL = os.getenv("PBX_URL", "").rstrip("/")
PBX_CLIENT_ID = os.getenv("PBX_CLIENT_ID", "")
PBX_CLIENT_SECRET = _secret("PBX_CLIENT_SECRET")
PBX_MANAGE_SECRETS = _b("PBX_MANAGE_SECRETS", "true")  # read or create SIP secrets via API
PBX_SCOPE = os.getenv("PBX_SCOPE", "gql:core:read gql:core:write gql:ringgroups")
PBX_RING_GROUP = os.getenv("PBX_RING_GROUP", "")  # new extensions join this ring group
PBX_SSH = os.getenv("PBX_SSH", "")  # user@host, used for Apply Config (the API can't)
PBX_SSH_KEY = os.getenv("PBX_SSH_KEY", "/secrets/pbx_ssh_key")
PBX_PRIVATE_EXTS = {e.strip() for e in os.getenv("PBX_PRIVATE_EXTS", "").split(",") if e.strip()}  # never offered to callers

# WalkieFleet
WF_URL = os.getenv("WF_URL", "")
WF_NETWORK_ID = os.getenv("WF_NETWORK_ID", "")
WF_CERT_FILE = os.getenv("WF_CERT_FILE", "/secrets/wf_cert.pem")
WF_ADMIN_PASSWORD = _secret("WF_ADMIN_PASSWORD")

# ElevenLabs phone operator
ELEVENLABS_API_KEY = _secret("ELEVENLABS_API_KEY")
ELEVENLABS_AGENT_ID = os.getenv("ELEVENLABS_AGENT_ID", "")
SIP_DOMAIN = os.getenv("SIP_DOMAIN", "")
SIP_PORT = int(os.getenv("SIP_PORT", "5060"))
SIP_TRANSPORT = os.getenv("SIP_TRANSPORT", "udp").lower()
SIP_PROXY = os.getenv("SIP_PROXY", "")  # optional outbound proxy host, default SIP_DOMAIN

# Which add-on apps to deploy & provision
ENABLED_APPS = [a.strip() for a in os.getenv("APPS", "traccar,linphone,nextcloud,davx5,rustdesk").split(",") if a.strip()]

# Package names
PKG = {
    "traccar": "org.traccar.client",
    "linphone": "org.linphone",
    "nextcloud": "com.nextcloud.client",
    "davx5": "at.bitfire.davdroid",
    "rustdesk": "com.carriez.flutter_hbb",
}
APP_LABEL = {
    "traccar": "Location",
    "linphone": "Phone (SIP)",
    "nextcloud": "Files & Photos",
    "davx5": "Contacts Sync",
    "rustdesk": "Remote Support",
}
