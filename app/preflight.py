"""Preflight provisioning.

Scanners (kics, 2ms): downloaded from the LATEST (non-prerelease) GitHub release,
checksum-verified, extracted, and registered in a manifest so scans can find them.
KICS also needs its query assets — if the release archive doesn't carry them, we
fetch them from the source tarball at the same tag, because KICS won't run without.

Package managers (mvn, gradle, npm, pip, dotnet, go): detected and GUIDED only.
Auto-installing a system package manager needs elevation, so it's never silent.

GitHub may be blocked or rate-limited on a sovereign network. Every failure path
returns a clear message + the manual URL. Set GITHUB_TOKEN to raise the API limit.
"""
from __future__ import annotations
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path

LOCAL_BIN = Path.home() / ".cxscan" / "bin"
MANIFEST = LOCAL_BIN / "installed.json"

TOOLS = {
    "kics":   {"kind": "scanner", "version": ["version"], "repo": "Checkmarx/kics", "needs_queries": True},
    "2ms":    {"kind": "scanner", "version": ["--version"], "repo": "Checkmarx/2ms", "needs_queries": False},
    "mvn":    {"kind": "pkgmgr", "version": ["-v"], "eco": "Java/Maven"},
    "gradle": {"kind": "pkgmgr", "version": ["-v"], "eco": "Java/Gradle"},
    "npm":    {"kind": "pkgmgr", "version": ["-v"], "eco": "Node"},
    "pip":    {"kind": "pkgmgr", "version": ["--version"], "eco": "Python"},
    "dotnet": {"kind": "pkgmgr", "version": ["--version"], "eco": ".NET"},
    "go":     {"kind": "pkgmgr", "version": ["version"], "eco": "Go"},
}

INSTALL_HINTS = {
    "linux": {"mvn": "apt-get install -y maven", "gradle": "apt-get install -y gradle",
              "npm": "apt-get install -y nodejs npm", "pip": "apt-get install -y python3-pip",
              "dotnet": "apt-get install -y dotnet-sdk-8.0", "go": "apt-get install -y golang-go"},
    "darwin": {"mvn": "brew install maven", "gradle": "brew install gradle",
               "npm": "brew install node", "pip": "brew install python",
               "dotnet": "brew install --cask dotnet-sdk", "go": "brew install go"},
    "windows": {"mvn": "winget install Apache.Maven", "gradle": "winget install Gradle.Gradle",
                "npm": "winget install OpenJS.NodeJS", "pip": "winget install Python.Python.3",
                "dotnet": "winget install Microsoft.DotNet.SDK.8", "go": "winget install GoLang.Go"},
}


def _os() -> str:
    s = platform.system().lower()
    return "darwin" if s == "darwin" else "windows" if s.startswith("win") else "linux"


def _arch_tokens() -> list[str]:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64", "x64"):
        return ["x86_64", "amd64", "x64"]
    if m in ("arm64", "aarch64"):
        return ["arm64", "aarch64"]
    return [m]


def _os_tokens() -> list[str]:
    return {"windows": ["windows", "win"], "darwin": ["darwin", "macos", "mac"],
            "linux": ["linux"]}[_os()]


# ---- manifest -----------------------------------------------------------------
def _load_manifest() -> dict:
    try:
        return json.loads(MANIFEST.read_text())
    except Exception:
        return {}


def _save_manifest(d: dict):
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(d, indent=2))


def resolve(name: str) -> dict | None:
    """Return {'path':..., 'queries':...} for an installed scanner, or None.
    Checks our managed manifest first, then PATH."""
    man = _load_manifest().get(name)
    if man and Path(man["path"]).exists():
        return man
    onpath = shutil.which(name)
    if onpath:
        info = {"path": onpath}
        if name == "kics":
            qp = os.environ.get("KICS_QUERIES_PATH")
            if qp:
                info["queries"] = qp
        return info
    return None


# ---- detection ----------------------------------------------------------------
@dataclass
class ToolStatus:
    name: str
    kind: str
    installed: bool
    path: str | None = None
    version: str | None = None
    eco: str | None = None
    install_hint: str | None = None
    can_autoinstall: bool = False


def _version(path: str, args: list[str]) -> str | None:
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=15)
        return (out.stdout or out.stderr).strip().splitlines()[0][:80]
    except Exception:
        return None


def detect() -> list[dict]:
    osname = _os()
    rows: list[ToolStatus] = []
    for name, spec in TOOLS.items():
        if spec["kind"] == "scanner":
            r = resolve(name)
            st = ToolStatus(name=name, kind="scanner", installed=bool(r),
                            path=(r or {}).get("path"))
            if r:
                st.version = _version(r["path"], spec["version"])
            else:
                st.can_autoinstall = True
        else:
            path = shutil.which(name)
            st = ToolStatus(name=name, kind="pkgmgr", installed=bool(path),
                            path=path, eco=spec.get("eco"))
            if path:
                st.version = _version(path, spec["version"])
            else:
                st.install_hint = INSTALL_HINTS.get(osname, {}).get(name)
        rows.append(st)
    return [asdict(r) for r in rows]


# ---- scanner download ---------------------------------------------------------
def _gh(url: str) -> bytes:
    headers = {"User-Agent": "cxscan", "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _latest_release(repo: str) -> dict:
    # /releases/latest is, by GitHub's definition, the latest NON-prerelease,
    # non-draft release — exactly what we want.
    return json.loads(_gh(f"https://api.github.com/repos/{repo}/releases/latest"))


def _pick_asset(assets: list[dict]) -> tuple[dict | None, dict | None]:
    ostok, archtok = _os_tokens(), _arch_tokens()
    checksum = None
    candidates = []
    for a in assets:
        n = a["name"].lower()
        if any(k in n for k in ("sha256", "checksum", ".sig", ".pem")):
            if "checksum" in n or "sha256" in n:
                checksum = a
            continue
        if any(o in n for o in ostok):
            score = 2 if any(x in n for x in archtok) else 1
            # prefer zip on windows, tar.gz elsewhere
            if _os() == "windows" and n.endswith(".zip"):
                score += 1
            if _os() != "windows" and (n.endswith(".tar.gz") or n.endswith(".tgz")):
                score += 1
            candidates.append((score, a))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return (candidates[0][1] if candidates else None), checksum


def _extract(archive: Path, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    n = archive.name.lower()
    if n.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
    elif n.endswith(".tar.gz") or n.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as t:
            t.extractall(dest)
    else:
        # raw binary
        shutil.copy2(archive, dest / archive.name)


def _find_binary(root: Path, name: str) -> Path | None:
    wanted = {name, f"{name}.exe"}
    for p in root.rglob("*"):
        if p.is_file() and p.name.lower() in wanted:
            return p
    return None


def _find_queries(root: Path) -> Path | None:
    for p in root.rglob("queries"):
        if p.is_dir() and (p.parent.name == "assets" or any(p.iterdir())):
            return p          # the queries dir itself (KICS -q expects this)
    return None


def _fetch_kics_queries(repo: str, tag: str, dest: Path) -> Path | None:
    """KICS queries live in the repo's assets/. Pull the source tarball at the
    same tag and extract assets/ (queries + libraries)."""
    url = f"https://github.com/{repo}/archive/refs/tags/{tag}.tar.gz"
    raw = dest / "src.tar.gz"
    raw.write_bytes(_gh(url))
    with tarfile.open(raw, "r:gz") as t:
        members = [m for m in t.getmembers() if "/assets/" in m.name]
        t.extractall(dest, members=members)
    raw.unlink(missing_ok=True)
    q = _find_queries(dest)
    return q


def download_scanner(name: str) -> dict:
    spec = TOOLS.get(name)
    if not spec or spec["kind"] != "scanner":
        return {"ok": False, "error": f"{name} is not an auto-installable scanner"}
    install_dir = LOCAL_BIN / name
    try:
        rel = _latest_release(spec["repo"])
        tag = rel["tag_name"]
        binary, checksum = _pick_asset(rel.get("assets", []))
        if not binary:
            return {"ok": False, "error": "no matching asset for this OS/arch",
                    "release": rel.get("html_url")}

        # download
        if install_dir.exists():
            shutil.rmtree(install_dir, ignore_errors=True)
        install_dir.mkdir(parents=True, exist_ok=True)
        data = _gh(binary["browser_download_url"])

        # verify
        verified = False
        if checksum:
            sums = _gh(checksum["browser_download_url"]).decode("utf-8", "replace")
            expected = next((ln.split()[0] for ln in sums.splitlines()
                             if binary["name"] in ln), None)
            if expected:
                if hashlib.sha256(data).hexdigest() != expected:
                    return {"ok": False, "error": "checksum mismatch — refusing to install"}
                verified = True

        archive = install_dir / binary["name"]
        archive.write_bytes(data)
        _extract(archive, install_dir)

        binpath = _find_binary(install_dir, name)
        if not binpath:
            return {"ok": False, "error": f"binary '{name}' not found after extraction",
                    "hint": "asset layout may have changed; check the release"}
        binpath.chmod(binpath.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        entry = {"path": str(binpath), "tag": tag, "checksum_verified": verified}
        if spec.get("needs_queries"):
            q = _find_queries(install_dir) or _fetch_kics_queries(spec["repo"], tag, install_dir)
            if not q:
                return {"ok": False, "error": "kics installed but queries not found",
                        "path": str(binpath)}
            entry["queries"] = str(q)
            libs = q.parent / "libraries"      # KICS needs assets/libraries too
            if libs.is_dir():
                entry["libraries"] = str(libs)

        man = _load_manifest(); man[name] = entry; _save_manifest(man)
        return {"ok": True, "name": name, "tag": tag, "path": str(binpath),
                "checksum_verified": verified, "queries": entry.get("queries"),
                "note": f"{name} {tag} installed to {install_dir}"}

    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"ok": False, "error": "GitHub API rate limit hit",
                    "fix": "set a GITHUB_TOKEN env var and retry, or install manually",
                    "manual": f"https://github.com/{spec['repo']}/releases/latest"}
        return {"ok": False, "error": f"HTTP {e.code}",
                "manual": f"https://github.com/{spec['repo']}/releases/latest"}
    except Exception as e:
        return {"ok": False, "error": str(e),
                "manual": f"download {name} from https://github.com/{spec['repo']}/releases/latest "
                          f"and place it at {install_dir}"}
