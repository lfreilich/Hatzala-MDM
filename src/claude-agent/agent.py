#!/usr/bin/env python3
"""hbs-claude-agent: runs Claude Code on the host for the ops dashboard's hidden /claude page.

Listens on 127.0.0.1 only and needs the shared token in stack/secrets/claude_agent_token, which only the
bridge container can read. The bridge lets owners (ADMIN_OWNERS) through; everyone else gets a 404.
One job runs at a time. Each job's stream-json output is kept in data/claude/<job>.jsonl, so a page
reload or a dropped connection doesn't lose it, and closing the browser doesn't stop the job.
"""
import hmac
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PREFIX = "/opt/hbs-addons"
TOKEN_FILE = f"{PREFIX}/stack/secrets/claude_agent_token"
JOB_DIR = f"{PREFIX}/stack/data/claude"
PORT = int(os.getenv("CLAUDE_AGENT_PORT", "8091"))
WORKDIR = os.getenv("CLAUDE_AGENT_CWD", "/root")  # same project (and memory) as an SSH session
TIMEOUT = int(os.getenv("CLAUDE_AGENT_TIMEOUT", "2700"))
CLAUDE = shutil.which("claude") or "/root/.local/bin/claude"
MAX_RESULT = 6000

SYSTEM = """You are being driven from the hidden /claude page of the HBS ops dashboard (https://ops.hatzala-mdm.com/claude) \
by the owner {actor}. Nobody can answer questions mid-run: if you need a decision, stop and ask in your final message. \
The live stack is /opt/hbs-addons (bridge/, stack/, src/). Follow the saved memory notes: after editing bridge/ \
mirror the change into src/, and rebuild the bridge with `cd /opt/hbs-addons/stack && docker compose up -d --build bridge`. \
Rebuilding the bridge restarts the dashboard this page runs in; the page reconnects by itself, and this job keeps running. \
Don't restart or stop hbs-claude-agent itself. Commit and push only when asked. Keep the final message short and plain."""

jobs: dict[str, dict] = {}
lock = threading.Lock()


def token() -> str:
    with open(TOKEN_FILE) as f:
        return f.read().strip()


def _trim(ev: dict) -> dict:
    """Tool results can be huge (file dumps); the page only needs the start."""
    msg = ev.get("message") if isinstance(ev.get("message"), dict) else None
    for block in (msg or {}).get("content") or []:
        if isinstance(block, dict) and block.get("type") == "tool_result":
            c = block.get("content")
            if isinstance(c, list):
                c = "\n".join(x.get("text", "") for x in c if isinstance(x, dict))
            if isinstance(c, str) and len(c) > MAX_RESULT:
                c = c[:MAX_RESULT] + f"\n... ({len(c) - MAX_RESULT} more characters)"
            block["content"] = c
    return ev


def _append(job: dict, ev: dict):
    ev = _trim(ev)
    ev["_t"] = time.time()
    with lock:
        job["events"].append(ev)
    with open(job["file"], "a") as f:
        f.write(json.dumps(ev) + "\n")


def _run(job: dict, prompt: str, resume: str | None, actor: str):
    cmd = [CLAUDE, "-p", "--output-format", "stream-json", "--verbose", "--permission-mode", "auto",
           "--append-system-prompt", SYSTEM.format(actor=actor)]
    if resume:
        cmd += ["--resume", resume]
    try:
        p = subprocess.Popen(cmd, cwd=WORKDIR, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1,
                             env={**os.environ, "HOME": "/root"}, start_new_session=True)
        job["proc"] = p
        p.stdin.write(prompt)
        p.stdin.close()
        killer = threading.Timer(TIMEOUT, lambda: p.kill())
        killer.start()
        for line in p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                ev = {"type": "log", "text": line}
            if ev.get("session_id"):
                job["session_id"] = ev["session_id"]
            _append(job, ev)
        p.wait()
        killer.cancel()
        if job.get("stopped"):
            _append(job, {"type": "log", "text": "Stopped from the page."})
        elif p.returncode:
            _append(job, {"type": "log", "text": f"Claude exited with code {p.returncode}."})
    except Exception as e:
        _append(job, {"type": "log", "text": f"Runner error: {e}"})
    finally:
        job["done"] = True
        job["finished"] = time.time()
        _save_index(job)


def _save_index(job: dict):
    entry = {k: job.get(k) for k in ("id", "actor", "prompt", "session_id", "started", "finished")}
    with open(f"{JOB_DIR}/index.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def _history(limit=30) -> list[dict]:
    try:
        with open(f"{JOB_DIR}/index.jsonl") as f:
            rows = [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        rows = []
    return rows[-limit:][::-1]


def _load(job_id: str) -> dict | None:
    if job_id in jobs:
        return jobs[job_id]
    if not job_id.isalnum():
        return None
    path = f"{JOB_DIR}/{job_id}.jsonl"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        events = [json.loads(l) for l in f if l.strip()]
    sid = next((e["session_id"] for e in events if e.get("session_id")), None)
    return {"id": job_id, "events": events, "done": True, "session_id": sid}


def running() -> dict | None:
    return next((j for j in jobs.values() if not j["done"]), None)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self) -> bool:
        if hmac.compare_digest(self.headers.get("X-Agent-Token", ""), token()):
            return True
        self._send(403, {"error": "forbidden"})
        return False

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n < 200_000 else {}

    def do_GET(self):
        if not self._auth():
            return
        path, _, qs = self.path.partition("?")
        args = dict(a.split("=", 1) for a in qs.split("&") if "=" in a)
        if path == "/status":
            r = running()
            return self._send(200, {"running": r and r["id"], "history": _history()})
        if path == "/events":
            job = _load(args.get("job", ""))
            if not job:
                return self._send(404, {"error": "no such job"})
            after = int(args.get("after", "0") or 0)
            with lock:
                evs = job["events"][after:]
            return self._send(200, {"events": evs, "next": after + len(evs), "done": job["done"],
                                    "session_id": job.get("session_id")})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        body = self._body()
        if self.path == "/run":
            prompt = (body.get("prompt") or "").strip()
            if not prompt:
                return self._send(400, {"error": "Empty request."})
            with lock:
                if running():
                    return self._send(409, {"error": "Claude is already working on something. Wait or stop it."})
                job_id = time.strftime("%Y%m%d%H%M%S") + secrets.token_hex(3)
                job = {"id": job_id, "events": [], "done": False, "actor": body.get("actor", "?"), "prompt": prompt[:500],
                       "started": time.time(), "session_id": body.get("resume"), "file": f"{JOB_DIR}/{job_id}.jsonl"}
                jobs[job_id] = job
            _append(job, {"type": "prompt", "text": prompt, "actor": job["actor"]})
            threading.Thread(target=_run, args=(job, prompt, body.get("resume") or None, job["actor"]),
                             daemon=True).start()
            return self._send(200, {"job": job_id})
        if self.path == "/stop":
            job = jobs.get(body.get("job", ""))
            if job and not job["done"] and job.get("proc"):
                job["stopped"] = True
                try:
                    os.killpg(job["proc"].pid, 15)
                except ProcessLookupError:
                    pass
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    os.makedirs(JOB_DIR, exist_ok=True)
    token()  # fail fast if the secret is missing
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
