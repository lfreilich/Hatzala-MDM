"""Tiny SQLite state store."""
import json
import sqlite3
import threading
import time

from . import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    number TEXT PRIMARY KEY,
    hmdm_id INTEGER,
    description TEXT,
    user_name TEXT,         -- person this device belongs to
    user_email TEXT,
    ext TEXT,               -- SIP extension
    sip_secret TEXT,
    prov_token TEXT,        -- Linphone provisioning token
    nc_user TEXT,
    nc_password TEXT,
    nc_app_password TEXT,
    traccar_id INTEGER,
    steps TEXT DEFAULT '{}',-- json: which one-time actions were done
    last_error TEXT,
    updated REAL
);
CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    org TEXT,
    title TEXT,
    phone TEXT,
    mobile TEXT,
    sip TEXT,
    email TEXT,
    note TEXT,
    source TEXT DEFAULT 'manual'  -- manual | pbx | device
);
CREATE TABLE IF NOT EXISTS events (
    ts REAL, level TEXT, device TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS linked_users (  -- WalkieFleet account <-> SIP extension <-> email
    login TEXT PRIMARY KEY, name TEXT, ext TEXT, email TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS wifi_networks (  -- offered on Add device; the chosen one goes in the enrollment QR
    id INTEGER PRIMARY KEY AUTOINCREMENT, ssid TEXT NOT NULL, password TEXT, security TEXT NOT NULL,
    hidden INTEGER DEFAULT 0, updated REAL
);
CREATE TABLE IF NOT EXISTS admin_requests (  -- proposed admins: no accounts and no gate access until an owner approves
    email TEXT PRIMARY KEY, name TEXT, requested_by TEXT, requested REAL
);
CREATE TABLE IF NOT EXISTS sso_accounts (  -- which app login each approved Google account signs in as
    email TEXT, app TEXT, login TEXT, password TEXT, PRIMARY KEY (email, app)
);
"""


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.executescript(SCHEMA)
            have = {r["name"] for r in _conn.execute("PRAGMA table_info(devices)")}
            for col in ("user_name", "user_email"):
                if col not in have:
                    _conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")
            _conn.commit()
        return _conn


def q(sql: str, args=()) -> list[sqlite3.Row]:
    with _lock:
        return conn().execute(sql, args).fetchall()


def x(sql: str, args=()) -> int:
    with _lock:
        c = conn().execute(sql, args)
        conn().commit()
        return c.lastrowid


def log(level: str, message: str, device: str | None = None):
    x("INSERT INTO events(ts, level, device, message) VALUES (?,?,?,?)", (time.time(), level, device, message[:2000]))
    x("DELETE FROM events WHERE ts < ?", (time.time() - 30 * 86400,))
    print(f"[{level}] {device or '-'}: {message}", flush=True)


def device(number: str) -> dict | None:
    r = q("SELECT * FROM devices WHERE number=?", (number,))
    if not r:
        return None
    d = dict(r[0])
    d["steps"] = json.loads(d.get("steps") or "{}")
    return d


def save_device(d: dict):
    d = dict(d)
    d["steps"] = json.dumps(d.get("steps") or {})
    d["updated"] = time.time()
    cols = ["number", "hmdm_id", "description", "user_name", "user_email", "ext", "sip_secret", "prov_token", "nc_user", "nc_password",
            "nc_app_password", "traccar_id", "steps", "last_error", "updated"]
    x(f"INSERT OR REPLACE INTO devices({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
      tuple(d.get(c) for c in cols))


def kv_get(k: str, default=None):
    r = q("SELECT v FROM kv WHERE k=?", (k,))
    return json.loads(r[0]["v"]) if r else default


def kv_set(k: str, v):
    x("INSERT OR REPLACE INTO kv(k, v) VALUES (?,?)", (k, json.dumps(v)))
