"""Engine runners. The tool clones ONCE, then every engine scans that local copy.

Each runner returns (report_paths: dict, native_exit: int). None of them gate —
gating is centralized in normalize/models against the parsed Findings.
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse


def _run(cmd, cwd=None, env=None) -> int:
    # NOTE: never log `cmd` directly when it may carry an auth token.
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return proc.returncode


def clone(git_url: str, ref: str, depth: int, auth: dict, dest: Path,
          log) -> Path:
    """Clone once into dest/src. Credentials are injected into the URL in-memory
    and never written to logs or to the on-disk config."""
    src = dest / "src"
    url = git_url
    user, token = (auth or {}).get("username"), (auth or {}).get("token")
    if user and token and git_url.startswith("http"):
        p = urlparse(git_url)
        url = urlunparse(p._replace(netloc=f"{user}:{token}@{p.netloc}"))
    cmd = ["git", "clone", "--branch", ref]
    if depth and depth > 0:
        cmd += ["--depth", str(depth)]
    cmd += [url, str(src)]
    log("cloning repository")            # deliberately not logging the URL+token
    if _run(cmd) != 0:
        raise RuntimeError("git clone failed (check ref / credentials / network)")
    return src


def run_kics(src: Path, out: Path, cfg: dict, log) -> tuple[dict, int]:
    out.mkdir(parents=True, exist_ok=True)
    from . import preflight
    r = preflight.resolve("kics")
    if not r:
        log("kics: binary not found — install it in the Setup tab")
        return ({}, 1)
    fmts = ",".join(cfg.get("reports", ["json", "sarif"]))
    cmd = [r["path"], "scan", "-p", str(src), "-o", str(out),
           "--report-formats", fmts, "--output-name", "kics",
           "--no-progress", "--ignore-on-exit", "results"]
    if r.get("queries"):
        cmd += ["-q", r["queries"]]
    if r.get("libraries"):
        cmd += ["--libraries-path", r["libraries"]]
    for sev in cfg.get("exclude_severities", []):
        cmd += ["--exclude-severities", sev]
    log("kics: scanning IaC")
    rc = _run(cmd)
    return ({"sarif": out / "kics.sarif", "json": out / "kics.json",
             "pdf": out / "kics.pdf"}, rc)


def run_twoms(src: Path, out: Path, cfg: dict, log) -> tuple[dict, int]:
    out.mkdir(parents=True, exist_ok=True)
    from . import preflight
    r = preflight.resolve("2ms")
    if not r:
        log("2ms: binary not found — install it in the Setup tab")
        return ({}, 1)
    sub = "git" if cfg.get("scan_git_history") else "filesystem"
    target = ["--path", str(src)] if sub == "filesystem" else [str(src)]
    cmd = [r["path"], sub, *target,
           "--report-path", str(out / "2ms.sarif"),
           "--report-path", str(out / "2ms.json"),
           "--ignore-on-exit", "results"]
    log("2ms: scanning for secrets")
    rc = _run(cmd)
    return ({"sarif": out / "2ms.sarif", "json": out / "2ms.json"}, rc)


def run_sca(src: Path, out: Path, cfg: dict, log) -> tuple[dict, int]:
    """SCA via the Checkmarx One `cx` CLI with Resolver. Resolution is local;
    only dependency metadata leaves. Auth is the CxOne API key (which the CLI
    uses to auto-derive base URL / tenant)."""
    out.mkdir(parents=True, exist_ok=True)
    cx = cfg.get("cx_path", "cx")
    resolver = cfg.get("resolver_path", "ScaResolver")
    api_key = cfg.get("api_key")
    if not api_key:
        log("sca: no CxOne API key — connect CxOne in the Setup tab")
        return ({}, 1)
    cmd = [cx, "scan", "create", "-s", str(src),
           "--project-name", cfg.get("project_name", "cxscan"),
           "--branch", cfg.get("branch", "main"),
           "--scan-types", "sca", "--sca-resolver", resolver,
           "--report-format", "json", "--output-name", "sca",
           "--output-path", str(out), "--apikey", api_key]
    if cfg.get("base_uri"):
        cmd += ["--base-uri", cfg["base_uri"]]
    if cfg.get("tenant"):
        cmd += ["--tenant", cfg["tenant"]]
    if cfg.get("no_upload_manifest"):
        cmd += ["--sca-resolver-params", "--no-upload-manifest"]
    log("sca: resolving locally, sending metadata to CxOne")
    rc = _run(cmd)
    return ({"json": out / "sca.json", "pdf": out / "sca.pdf"}, rc)


def run_sast(src: Path, out: Path, cfg: dict, log) -> tuple[dict, int]:
    """CxSAST on-prem via REST. Source is uploaded to YOUR manager (stays internal)."""
    from . import cxsast
    return cxsast.run(src, out, cfg, log)


RUNNERS = {"kics": run_kics, "twoms": run_twoms, "sca": run_sca, "sast": run_sast}
