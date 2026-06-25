"""cxscan backend — start scans, poll per-engine status, serve the dashboard.

Scans run in a background thread; each engine reports live status. Findings are
parsed into one model and gated per engine. In-memory store (swap for a real DB
before multi-user use; results contain sensitive secret locations)."""
from __future__ import annotations
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .models import EngineThreshold, resolve_env
from . import engines, normalize, preflight, pipeline, connections, auth, github_oauth

app = FastAPI(title="cxscan")
app.add_middleware(auth.BasicAuthMiddleware)
STATIC = Path(__file__).resolve().parent.parent / "static"
RUNS: dict[str, dict] = {}            # scan_id -> state
PARSERS = {"kics": ("sarif", normalize.parse_sarif, "kics"),
           "twoms": ("sarif", normalize.parse_sarif, "twoms"),
           "sca": ("json", normalize.parse_sca_json, None),
           "sast": ("json", normalize.parse_sast_json, None)}


class StartRequest(BaseModel):
    config_path: str = "config.example.yaml"
    git_url: str | None = None
    git_ref: str | None = None
    engines: list[str] | None = None      # subset to enable; None = config default


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scan_one(engine, cfg, src, run_dir, state):
    eng_state = state["engines"][engine]
    eng_state.update(status="running", started=_now())

    def log(msg):
        eng_state["log"].append(msg)

    try:
        paths, rc = engines.RUNNERS[engine](src, run_dir / engine, cfg, log)
        kind, parser, label = PARSERS[engine]
        report = paths.get(kind)
        findings = []
        if report and Path(report).exists():
            findings = parser(Path(report), label) if label else parser(Path(report))
        passed, reasons = EngineThreshold.from_config(
            cfg.get("threshold", {})).evaluate(findings)
        eng_state.update(
            status="done", finished=_now(), native_exit=rc,
            findings=[f.public(state["redact"]) for f in findings],
            counts=_count(findings), gate="pass" if passed else "fail",
            gate_reasons=reasons,
            reports={k: str(v) for k, v in paths.items() if Path(v).exists()})
    except Exception as e:                       # one engine failing != scan dead
        eng_state.update(status="failed", finished=_now(),
                         error=str(e), trace=traceback.format_exc().splitlines()[-3:])


def _count(findings):
    c = {}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def _run_scan(scan_id, raw_cfg):
    state = RUNS[scan_id]
    try:
        cfg = resolve_env(raw_cfg)
        # Live connections (Setup tab) override config creds — secrets never on disk.
        sast_conn = connections.get("sast")
        if sast_conn and "sast" in cfg["engines"]:
            cfg["engines"]["sast"].update(
                server_url=sast_conn["server_url"], username=sast_conn["username"],
                password=sast_conn["password"])
            if sast_conn.get("team_id") is not None:   # team picked in the UI
                cfg["engines"]["sast"]["team_id"] = sast_conn["team_id"]
        cx = connections.get("cxone")
        if cx and "sca" in cfg["engines"]:
            cfg["engines"]["sca"].update(
                api_key=cx["api_key"], base_uri=cx["base_uri"], tenant=cx["tenant"])
        # Stored Git creds for the clone host (if the form repo is private).
        git_auth = connections.git_auth_for(cfg["input"]["git_url"])
        if git_auth:
            cfg["input"]["git_auth"] = git_auth
        run_dir = Path(cfg.get("output", {}).get("results_dir", "./runs")) / scan_id
        run_dir.mkdir(parents=True, exist_ok=True)
        inp = cfg["input"]
        src = engines.clone(inp["git_url"], inp.get("git_ref", "main"),
                            inp.get("clone_depth", 0), inp.get("git_auth", {}),
                            run_dir, lambda m: state.setdefault("clone_log", []).append(m))
        state["status"] = "scanning"
        active = [e for e, c in cfg["engines"].items() if c.get("enabled")]
        with ThreadPoolExecutor(max_workers=len(active) or 1) as pool:
            futs = [pool.submit(_scan_one, e, cfg["engines"][e], src, run_dir, state)
                    for e in active]
            for f in futs:
                f.result()
        gates = [state["engines"][e].get("gate") for e in active]
        state["status"] = "completed"
        state["overall_gate"] = "fail" if "fail" in gates else "pass"
    except Exception as e:
        state["status"] = "failed"
        state["error"] = str(e)
    state["finished"] = _now()


@app.post("/api/scans")
def start_scan(req: StartRequest):
    path = Path(req.config_path)
    if not path.exists():
        raise HTTPException(404, f"config not found: {req.config_path}")
    raw_cfg = yaml.safe_load(path.read_text())

    # Form overrides — this is what makes the Scan tab actually drive the run.
    if req.git_url:
        raw_cfg.setdefault("input", {})["git_url"] = req.git_url
    if req.git_ref:
        raw_cfg.setdefault("input", {})["git_ref"] = req.git_ref
    if req.engines is not None:
        for name, ecfg in raw_cfg.get("engines", {}).items():
            ecfg["enabled"] = name in req.engines

    scan_id = uuid.uuid4().hex[:12]
    RUNS[scan_id] = {
        "id": scan_id, "status": "starting", "started": _now(),
        "redact": raw_cfg.get("output", {}).get("redact_secret_values", True),
        "overall_gate": None,
        "engines": {e: {"status": "pending", "log": [], "findings": [],
                        "counts": {}, "gate": None}
                    for e, c in raw_cfg["engines"].items() if c.get("enabled")},
    }
    threading.Thread(target=_run_scan, args=(scan_id, raw_cfg), daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in RUNS:
        raise HTTPException(404, "unknown scan")
    return JSONResponse(RUNS[scan_id])


@app.get("/api/scans")
def list_scans():
    return [{"id": s["id"], "status": s["status"], "started": s["started"],
             "overall_gate": s.get("overall_gate")} for s in RUNS.values()]


class SastConn(BaseModel):
    url: str
    username: str
    password: str


class CxOneConn(BaseModel):
    api_key: str


@app.get("/api/connections")
def get_connections():
    """Non-secret status of configured connections."""
    return {**connections.status(), "app_auth": auth.enabled()}


@app.post("/api/connections/sast")
def connect_sast(c: SastConn):
    """Test CxSAST URL+creds (mints a token) and store in memory. Returns teams."""
    return connections.sast_test_and_store(c.url, c.username, c.password)


@app.post("/api/connections/cxone")
def connect_cxone(c: CxOneConn):
    """Decode the API key, derive tenant+URLs, refresh a token, ping the tenant."""
    return connections.cxone_test_and_store(c.api_key)


class SastTeam(BaseModel):
    team_id: int
    team_name: str | None = None


@app.post("/api/connections/sast/team")
def select_sast_team(t: SastTeam):
    """Pick the CxSAST team SAST scans create the project under (UI click)."""
    return connections.set_sast_team(t.team_id, t.team_name)


class GitConn(BaseModel):
    repo_url: str
    username: str
    token: str


@app.post("/api/connections/git")
def connect_git(c: GitConn):
    """Validate git creds via ls-remote on the given repo; store by host."""
    return connections.git_test_and_store(c.repo_url, c.username, c.token)


@app.get("/api/connections/git/github")
def github_oauth_status():
    """Whether the GitHub OAuth button is usable (client id configured)."""
    return {"configured": github_oauth.configured()}


@app.post("/api/connections/git/github/start")
def github_oauth_start():
    """Begin the GitHub device flow — returns a user code + verification URL."""
    return github_oauth.start()


class DeviceCode(BaseModel):
    device_code: str


@app.post("/api/connections/git/github/poll")
def github_oauth_poll(c: DeviceCode):
    """Poll once for the token; on success the github.com creds are stored."""
    return github_oauth.poll(c.device_code)


@app.get("/api/preflight")
def get_preflight():
    """Which scanners/package managers are present, and how to get the rest."""
    return preflight.detect()


@app.post("/api/preflight/install/{name}")
def install_scanner(name: str):
    """Download + checksum-verify a scanner (kics/2ms) from GitHub releases."""
    return preflight.download_scanner(name)


@app.get("/api/pipeline/{provider}")
def get_pipeline(provider: str, config_path: str = "config.example.yaml"):
    if provider not in pipeline.GENERATORS:
        raise HTTPException(404, f"unknown provider: {provider}")
    raw_cfg = yaml.safe_load(Path(config_path).read_text())
    return {"provider": provider, "snippet": pipeline.GENERATORS[provider](raw_cfg)}


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "dashboard.html")
