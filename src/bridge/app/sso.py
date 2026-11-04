"""Single sign-on: after the Google gate, sign the browser in to the apps that have their own login.

Each app is reached at https://<app host>/hbs-sso, which Caddy puts behind the gate. The bridge logs
in as that person's own app account (sso_accounts) and hands the session cookies to the browser.
A Google account with no entry gets no cookies, so it just sees the app's login page.
AdGuard is not here because Caddy already sends its one admin login on every request.
"""
import hashlib
import re

import httpx

from . import config, db
from .clients import ApiError, TIMEOUT


def _headwind(login: str, password: str) -> list[str]:
    md5 = hashlib.md5(password.encode()).hexdigest().upper()
    r = httpx.post(f"{config.HMDM_URL.rstrip('/')}/rest/public/auth/login", timeout=TIMEOUT,
                   json={"login": login, "password": md5})
    if r.status_code != 200 or r.json().get("status") != "OK":
        raise ApiError(f"Headwind login -> {r.status_code}")
    return r.headers.get_list("set-cookie")


def _traccar(login: str, password: str) -> list[str]:
    r = httpx.post(f"{config.TRACCAR_URL}/api/session", timeout=TIMEOUT,
                   data={"email": login, "password": password})
    if r.status_code != 200:
        raise ApiError(f"Traccar login -> {r.status_code}")
    return r.headers.get_list("set-cookie")


def _nextcloud(login: str, password: str) -> list[str]:
    """Submit the login form. Cookies go by hand: httpx won't send Secure ones over local http."""
    base = {"Host": config.NC_HOST, "X-Forwarded-Proto": "https"}

    def cookie_header(cookies: list[str]) -> str:
        return "; ".join({c.split("=", 1)[0]: c.split(";", 1)[0] for c in cookies}.values())

    page = httpx.get(f"{config.NC_URL}/login", headers=base, timeout=TIMEOUT)
    token = re.search(r'data-requesttoken="([^"]+)"', page.text)
    if not token:
        raise ApiError(f"Nextcloud login page -> {page.status_code}")
    cookies = page.headers.get_list("set-cookie")
    r = httpx.post(f"{config.NC_URL}/login", timeout=TIMEOUT,
                   headers={**base, "Cookie": cookie_header(cookies),
                            "Origin": f"https://{config.NC_HOST}"},
                   data={"user": login, "password": password,
                         "requesttoken": token.group(1), "timezone": "UTC", "timezone_offset": "0"})
    if r.status_code != 303 or "/login" in r.headers.get("location", ""):
        raise ApiError(f"Nextcloud login -> {r.status_code}")
    return cookies + r.headers.get_list("set-cookie")


def login_cookies(host: str, email: str) -> list[str]:
    """Set-Cookie values for this person on this app's host, marked Secure: the edge is HTTPS."""
    apps = {config.DOMAIN: ("headwind", _headwind), config.MAP_HOST: ("traccar", _traccar),
            config.NC_HOST: ("nextcloud", _nextcloud)}
    if host not in apps:
        raise ApiError(f"No single sign-on for {host}")
    app, login = apps[host]
    rows = db.q("SELECT login, password FROM sso_accounts WHERE email=? AND app=?", (email.lower(), app))
    if not rows:
        return []
    cookies = login(rows[0]["login"], rows[0]["password"])
    return [c if re.search(r";\s*secure", c, re.I) else c + "; Secure" for c in cookies]
