"""CxSAST on-prem (v8.6+) REST runner.

Drives the async API so the orchestrator gets real status for the live lane.
On-prem: the zipped clone is uploaded to YOUR CxSAST manager — source stays in
the org. Endpoints follow the documented v8.6+ flow; validate preset/team IDs
against your tenant. Uses only the stdlib (urllib) to avoid extra deps.
"""
from __future__ import annotations
import json
import time
import zipfile
import urllib.request
import urllib.parse
from pathlib import Path

# Fixed client for the resource-owner password grant on CxSAST.
_CLIENT_ID = "resource_owner_client"
_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"
_TERMINAL = {"Finished", "Failed", "Canceled", "Deleted"}


def _req(url, method="GET", headers=None, data=None, want_json=True, raw=False):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(r, timeout=120) as resp:
        body = resp.read()
    if raw:
        return body
    if not body:
        return {}
    return json.loads(body) if want_json else body


def _auth(base, user, pwd) -> str:
    data = urllib.parse.urlencode({
        "username": user, "password": pwd, "grant_type": "password",
        "scope": "sast_rest_api", "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
    }).encode()
    tok = _req(f"{base}/cxrestapi/auth/identity/connect/token", "POST",
               {"Content-Type": "application/x-www-form-urlencoded"}, data)
    return tok["access_token"]


def _zip_source(src: Path, dest: Path) -> Path:
    z = dest / "source.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src.rglob("*"):
            if p.is_file() and ".git/" not in str(p):
                zf.write(p, p.relative_to(src))
    return z


def run(src: Path, out: Path, cfg: dict, log) -> tuple[dict, int]:
    out.mkdir(parents=True, exist_ok=True)
    base = cfg["server_url"].rstrip("/")
    hdr = lambda t: {"Authorization": f"Bearer {t}"}

    log("sast: authenticating")
    token = _auth(base, cfg["username"], cfg["password"])
    auth = hdr(token)
    jauth = {**auth, "Content-Type": "application/json"}

    # Project: find existing by name, else create under the configured team.
    log("sast: resolving project")
    projects = _req(f"{base}/cxrestapi/projects", headers=auth)
    name = cfg.get("project_name", "cxscan")
    pid = next((p["id"] for p in projects if p.get("name") == name), None)
    if pid is None:
        body = json.dumps({"name": name, "owningTeam": cfg["team_id"],
                           "isPublic": True}).encode()
        pid = _req(f"{base}/cxrestapi/projects", "POST", jauth, body)["id"]

    # Upload zipped local clone (multipart/form-data).
    log("sast: uploading source (stays on-prem)")
    zpath = _zip_source(src, out)
    boundary = "----cxscan7f1a"
    pre = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"zippedSource\";"
           f" filename=\"source.zip\"\r\nContent-Type: application/zip\r\n\r\n").encode()
    body = pre + zpath.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    _req(f"{base}/cxrestapi/projects/{pid}/sourceCode/attachments", "POST",
         {**auth, "Content-Type": f"multipart/form-data; boundary={boundary}"},
         body, want_json=False)

    # Trigger scan.
    log("sast: queuing scan")
    sbody = json.dumps({"projectId": pid, "isIncremental": cfg.get("incremental", False),
                        "isPublic": True, "forceScan": True,
                        "comment": "cxscan orchestrated"}).encode()
    scan_id = _req(f"{base}/cxrestapi/sast/scans", "POST", jauth, sbody)["id"]

    # Poll scan status.
    poll, every, waited = cfg.get("timeout_s", 3600), 10, 0
    status = "New"
    while waited < poll:
        s = _req(f"{base}/cxrestapi/sast/scans/{scan_id}", headers=auth)
        status = (s.get("status") or {}).get("name", "Unknown")
        log(f"sast: scan {status.lower()}")
        if status in _TERMINAL:
            break
        time.sleep(every); waited += every
    if status != "Finished":
        return ({}, 1)

    # Generate + download reports. XML drives the dashboard; PDF is the artifact.
    paths = {}
    for rtype in [r.upper() for r in cfg.get("reports", ["XML", "PDF"])]:
        rb = json.dumps({"reportType": rtype, "scanId": scan_id}).encode()
        rid = _req(f"{base}/cxrestapi/reports/sastScan", "POST", jauth, rb)["reportId"]
        for _ in range(60):
            st = _req(f"{base}/cxrestapi/reports/sastScan/{rid}/status", headers=auth)
            if (st.get("status") or {}).get("value") == "Created":
                break
            time.sleep(3)
        data = _req(f"{base}/cxrestapi/reports/sastScan/{rid}", headers=auth,
                    want_json=False, raw=True)
        fp = out / f"sast.{rtype.lower()}"
        fp.write_bytes(data)
        paths[rtype.lower()] = fp
    return (paths, 0)
