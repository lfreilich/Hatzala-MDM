"""Hidden /claude page: owners ask Claude Code (running on the host) to change the stack.

Not linked from the menu. Anyone who isn't an owner gets a plain 404, so the page doesn't show up for them.
The work happens in hbs-claude-agent (host systemd service on 127.0.0.1:8091); this module only proxies.
"""
import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from . import admins, db

AGENT = "http://127.0.0.1:8091"
TOKEN_FILE = "/secrets/claude_agent_token"
router = APIRouter()


def _owner(request: Request) -> str:
    actor = request.headers.get("Remote-Email", "").strip().lower()
    if not admins.is_owner(actor):
        raise HTTPException(404)
    return actor


def _api(request: Request) -> str:
    """JSON calls need a custom header, which a cross-site form or image can't send."""
    actor = _owner(request)
    if request.headers.get("X-HBS") != "1":
        raise HTTPException(403)
    return actor


def _agent(method: str, path: str, **kw):
    try:
        with open(TOKEN_FILE) as f:
            token = f.read().strip()
        r = httpx.request(method, AGENT + path, headers={"X-Agent-Token": token}, timeout=15, **kw)
    except (OSError, httpx.HTTPError) as e:
        return JSONResponse({"error": f"The Claude agent on the host isn't answering ({e.__class__.__name__}). "
                                      "Check: systemctl status hbs-claude-agent"}, status_code=502)
    return JSONResponse(r.json(), status_code=r.status_code, headers={"Cache-Control": "no-store"})


def register(app, templates, ctx):
    @app.get("/claude", response_class=HTMLResponse, include_in_schema=False)
    def claude_page(request: Request):
        _owner(request)
        return templates.TemplateResponse("claude.html", ctx(request), headers={"Cache-Control": "no-store"})

    @app.get("/claude/api/status", include_in_schema=False)
    def claude_status(request: Request):
        _api(request)
        return _agent("GET", "/status")

    @app.get("/claude/api/events", include_in_schema=False)
    def claude_events(request: Request, job: str, after: int = 0):
        _api(request)
        return _agent("GET", "/events", params={"job": job, "after": after})

    @app.post("/claude/api/run", include_in_schema=False)
    async def claude_run(request: Request):
        actor = _api(request)
        body = await request.json()
        prompt = str(body.get("prompt") or "")[:20000]
        db.log("info", f"Claude page request by {actor}: {prompt[:300]}")
        return _agent("POST", "/run", json={"prompt": prompt, "resume": body.get("resume") or None, "actor": actor})

    @app.post("/claude/api/stop", include_in_schema=False)
    async def claude_stop(request: Request):
        actor = _api(request)
        body = await request.json()
        db.log("info", f"Claude page job stopped by {actor}")
        return _agent("POST", "/stop", json={"job": str(body.get("job") or "")})
