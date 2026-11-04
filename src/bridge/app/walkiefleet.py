"""WalkieFleet server client (the management console's private WebSocket protocol).

There is no per-user write: changing one user means saving the whole network's settings. So every
write backs up first, changes one field, then re-reads and compares everything and restores on any
other difference.
"""
import asyncio
import base64
import copy
import json
import os
import ssl
import threading
import time
import uuid

import websockets

from . import config
from .clients import ApiError

_write_lock = threading.Lock()


def _id() -> str:
    return base64.b64encode(uuid.uuid4().bytes).decode()


def _ssl() -> ssl.SSLContext:
    # WalkieFleet has a self-signed certificate on an IP address, so trust exactly that certificate.
    # Its key is too short for OpenSSL's default level; it is still verified against the pinned copy.
    ctx = ssl.create_default_context(cafile=config.WF_CERT_FILE)
    ctx.check_hostname = False
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


class _Session:
    def __init__(self, ws):
        self.ws, self.nets, self.settings = ws, {}, {}

    async def pump(self, done, timeout: float) -> bool:
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            if done():
                return True
            try:
                raw = await asyncio.wait_for(self.ws.recv(), max(0.05, min(1, end - loop.time())))
            except asyncio.TimeoutError:
                continue
            for m in json.loads(raw):
                kind = m.get("MessageID")
                if kind == "PING":
                    await self.ws.send('[{"MessageID":"PONG"}]')
                elif kind == "CONFIG_SERVER_RESPONSE_ACK":
                    await self.ws.send('[{"MessageID":"LOGIN"}]')
                elif kind == "CONFIG_SERVER_RESPONSE_NACK":
                    raise ApiError(f"WalkieFleet login: {m.get('Reason')}")
                elif kind == "DATAEX" and m.get("DataType") == 100:
                    for n in m.get("DataObjects") or []:
                        self.nets[n["ID"]] = n
                elif kind == "DATAEX" and m.get("DataType") == 110 and m.get("DataObjects"):
                    self.settings[m["DataObjects"][0]["ID"]] = m["DataObjects"][0]
        return done()

    async def read(self, network: str) -> dict:
        self.settings.pop(network, None)
        await self.ws.send(json.dumps([{"MessageID": "SRV_GET_NETWORKSETTINGS", "ID": network}]))
        if not await self.pump(lambda: network in self.settings, 10):
            raise ApiError("WalkieFleet did not return the network settings")
        return self.settings[network]

    async def save(self, network: str, settings: dict):
        await self.ws.send(json.dumps([{"MessageID": "SRV_SET_NETWORKSETTINGS", "NetworkData": self.nets[network],
                                        "NetworkSettings": settings}]))
        await self.pump(lambda: False, 5)


async def _with_session(network, fn):
    async with websockets.connect(config.WF_URL, ssl=_ssl(), open_timeout=10, max_size=None) as ws:
        s = _Session(ws)
        await asyncio.wait_for(ws.recv(), 5)
        await ws.send(json.dumps([{
            "MessageID": "DEVICE_CONFIG", "Ssrc": 1, "AppName": "RemoteServerManager", "VersionName": "5.8.4",
            "VersionCode": 1, "AudioCodec": 1, "VoiceOverTcp": "True", "Password": config.WF_ADMIN_PASSWORD,
            "DeviceData": {"SessionID": _id(), "ID": _id(), "Login": "administrator", "AvatarHash": "",
                           "DeviceDescription": "MANUFACTURER=WLLC;MODEL=APIClientWEB;SERIAL=123456789;OSVERSION=5.0",
                           "VoiceOverTcp": True, "StatusID": "AAAAAAAAAAAAAAAAAAAAAA=="}}]))
        if not await s.pump(lambda: network in s.nets, 10):
            raise ApiError("WalkieFleet network not found")
        return await fn(s)


def _normal(settings: dict) -> dict:
    """Settings with lists sorted by ID, so a change of order doesn't count as a difference."""
    out = copy.deepcopy(settings)
    for v in out.values():
        if isinstance(v, list) and v and isinstance(v[0], dict) and "ID" in v[0]:
            v.sort(key=lambda x: x["ID"])
    return out


def users(network: str | None = None) -> list[dict]:
    network = network or config.WF_NETWORK_ID

    async def fn(s):
        return (await s.read(network))["Users"]

    return asyncio.run(_with_session(network, fn))


def set_sip_id(login: str, sip_id: str, network: str | None = None) -> bool:
    """Set one user's SipID. True if it was saved, False if it already had that value."""
    network = network or config.WF_NETWORK_ID

    async def fn(s):
        before = copy.deepcopy(await s.read(network))
        match = [u for u in before["Users"] if u.get("Login") == login]
        if len(match) != 1:
            raise ApiError(f"WalkieFleet user {login} not found")
        if match[0].get("SipID") == sip_id:
            return False
        path = os.path.join(os.path.dirname(config.DB_PATH), f"wf-settings-{int(time.time())}.json")
        with open(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            json.dump(before, f)
        wanted = copy.deepcopy(before)
        next(u for u in wanted["Users"] if u.get("Login") == login)["SipID"] = sip_id
        await s.save(network, wanted)
        after = await s.read(network)
        if _normal(after) != _normal(wanted):
            await s.save(network, before)
            restored = _normal(await s.read(network)) == _normal(before)
            raise ApiError(f"WalkieFleet save changed more than expected, {'restored' if restored else 'RESTORE FAILED'}"
                           f" (backup {os.path.basename(path)})")
        return True

    with _write_lock:
        return asyncio.run(_with_session(network, fn))
