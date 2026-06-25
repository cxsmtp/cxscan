"""Turn each engine's native report into unified Findings.

KICS + 2ms: SARIF-native, parsed fully here.
SCA (Resolver JSON) + SAST (CxSAST XML): adapters below. The field paths are the
documented shapes, but FINALIZE against a real report from the Prudential tenant —
schemas vary by version. Each adapter is isolated so swapping it is a one-function change.
"""
from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import (Finding, normalize_sev, SARIF_LEVEL_MAP, KICS_SEV_MAP,
                     SCA_MAP, SAST_MAP)


def _load_json(p: Path):
    return json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))


# ---- SARIF (KICS, 2ms) -------------------------------------------------------
def parse_sarif(path: Path, engine: str) -> list[Finding]:
    doc = _load_json(path)
    out: list[Finding] = []
    for run in doc.get("runs", []):
        rules = {r.get("id"): r for r in
                 run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            props = res.get("properties", {}) or {}
            # KICS exposes a real severity in properties; 2ms falls back to level.
            raw_sev = props.get("severity") or props.get("Severity")
            if raw_sev and engine == "kics":
                sev = normalize_sev(raw_sev, KICS_SEV_MAP)
            else:
                sev = SARIF_LEVEL_MAP.get(res.get("level", "warning"), "MEDIUM")
            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            extra = {k: v for k, v in props.items() if k.lower() != "severity"}
            help_txt = ((rule.get("help") or {}).get("text")
                        or (rule.get("fullDescription") or {}).get("text"))
            if help_txt:
                extra["remediation"] = help_txt[:1200]
            out.append(Finding(
                engine=engine,
                rule_id=rule_id,
                title=(rule.get("name") or rule.get("shortDescription", {})
                       .get("text") or rule_id or "finding"),
                severity=sev,
                file=art.get("uri"),
                line=region.get("startLine"),
                description=(res.get("message", {}) or {}).get("text", ""),
                extra=extra,
            ))
    return out


# ---- SCA (CxOne CLI / Resolver JSON) ----------------------------------------
def parse_sca_json(path: Path) -> list[Finding]:
    """Parse SCA results JSON. Handles two shapes, newest first:

    1. CxOne `cx` CLI  `--report-format json` -> {"results": [{type:"sca", ...}]}
    2. SCA Resolver risk-report               -> {"Vulnerabilities": [...]}

    Both are isolated here; field paths follow the documented schemas. Validate
    against a real report from your tenant — vendor JSON drifts between versions.
    """
    data = _load_json(path)
    # Shape 1: CxOne CLI report. `results` is a flat list typed per engine.
    cx_results = data.get("results")
    if isinstance(cx_results, list):
        sca = [r for r in cx_results
               if (r.get("type") or "").lower() in ("sca", "sca-vulnerability")]
        if sca:
            return [_sca_from_cxone(r) for r in sca]
    # Shape 2: Resolver risk-report.
    vulns = data.get("Vulnerabilities") or data.get("vulnerabilities") or []
    return [_sca_from_resolver(v) for v in vulns]


def _sca_from_cxone(r: dict) -> Finding:
    d = r.get("data") or {}
    vd = r.get("vulnerabilityDetails") or {}
    pkg = (d.get("packageIdentifier") or d.get("packageName")
           or r.get("packageName") or "")
    ver = d.get("packageVersion") or r.get("packageVersion") or ""
    cve = (vd.get("cveName") or r.get("cveName") or r.get("id")
           or d.get("queryName") or "SCA")
    fixed = d.get("recommendedVersion") or r.get("recommendedVersion")
    refs = [x.get("url") for x in (vd.get("references") or []) if x.get("url")]
    return Finding(
        engine="sca",
        rule_id=cve,
        title=f"{pkg}@{ver}: {cve}".strip(": ") or cve,
        severity=normalize_sev(r.get("severity") or vd.get("severity"), SCA_MAP),
        file=pkg or None,
        description=r.get("description") or vd.get("description") or "",
        extra={"package": pkg, "version": ver, "cve": cve, "fixed_version": fixed,
               "cvss": vd.get("cvssScore") or vd.get("cvss"),
               "cwe": vd.get("cweId"), "references": refs[:5]},
    )


def _sca_from_resolver(v: dict) -> Finding:
    pkg = v.get("PackageName") or v.get("packageName") or ""
    ver = v.get("PackageVersion") or v.get("version") or ""
    cve = v.get("Cve") or v.get("cveName") or v.get("id") or "SCA"
    fixed = (v.get("RecommendedVersion") or v.get("recommendedVersion")
             or v.get("fixResolutionText") or v.get("fixedVersion"))
    return Finding(
        engine="sca",
        rule_id=cve,
        title=f"{pkg}@{ver}: {cve}".strip(": ") or cve,
        severity=normalize_sev(v.get("Severity") or v.get("severity"), SCA_MAP),
        file=pkg or None,
        description=v.get("Description") or v.get("description") or "",
        extra={"package": pkg, "version": ver, "cve": cve, "fixed_version": fixed,
               "cvss": v.get("Score") or v.get("cvssScore"),
               "references": (v.get("References") or v.get("references") or [])[:5]},
    )


# ---- SAST (JSON: unified findings written by the REST flow, or raw OData) ----
# CxSAST report generation does NOT emit JSON (only PDF/RTF/CSV/XML), so the JSON
# path is produced via the REST API flow (see cxsast.py) and read back here. We
# also tolerate a raw OData results page ({"value": [...]}) for forward-compat.
_SAST_INT_SEV = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def parse_sast_json(path: Path) -> list[Finding]:
    data = _load_json(path)
    rows = (data if isinstance(data, list)
            else data.get("findings") or data.get("value") or [])
    out: list[Finding] = []
    for r in rows:
        # Unified shape (what cxscan writes) round-trips straight to a Finding.
        if "engine" in r and "severity" in r and isinstance(r.get("severity"), str):
            out.append(Finding(
                engine="sast", rule_id=r.get("rule_id", "SAST"),
                title=r.get("title", "SAST"), severity=r["severity"],
                file=r.get("file"), line=r.get("line"),
                description=r.get("description", ""), extra=r.get("extra", {}) or {}))
            continue
        # Raw OData/REST result: severity may be an int or a string.
        raw_sev = r.get("Severity", r.get("severity"))
        sev = (_SAST_INT_SEV.get(raw_sev) if isinstance(raw_sev, int)
               else normalize_sev(raw_sev, SAST_MAP))
        out.append(Finding(
            engine="sast",
            rule_id=str(r.get("QueryId") or r.get("queryId") or r.get("rule_id") or "SAST"),
            title=r.get("QueryName") or r.get("queryName") or r.get("title") or "SAST",
            severity=sev,
            file=r.get("FileName") or r.get("fileName") or r.get("file"),
            line=r.get("Line") or r.get("line"),
            description=r.get("Comment") or r.get("description") or "",
            extra={"state": r.get("StateId") or r.get("state"),
                   "status": r.get("Status") or r.get("status"),
                   "similarity_id": r.get("SimilarityId")}))
    return out


# ---- SAST (legacy CxSAST XML report) ----------------------------------------
def parse_sast_xml(path: Path) -> list[Finding]:
    """ADAPTER — verify against a real CxSAST 9.x XML report. Schema:
    <CxXMLResults><Query name= Severity=...><Result FileName= Line=...>
      <Path><PathNode><FileName/><Line/><Name/></PathNode>...</Path></Result></Query>."""
    root = ET.parse(path).getroot()
    out: list[Finding] = []
    for query in root.iter("Query"):
        qname = query.get("name", "SAST")
        qsev = query.get("Severity") or query.get("severity")
        for r in query.findall("Result"):
            # data-flow nodes: source (first) -> sink (last)
            nodes = []
            for pn in r.findall(".//PathNode"):
                fn = (pn.findtext("FileName") or "").strip()
                ln = (pn.findtext("Line") or "").strip()
                nm = (pn.findtext("Name") or "").strip()
                if fn or nm:
                    nodes.append({"file": fn, "line": ln, "name": nm})
            extra = {"state": r.get("state"), "status": r.get("Status"),
                     "deeplink": r.get("DeepLink")}
            if nodes:
                extra["flow"] = nodes[:40]
                extra["source"] = nodes[0]
                extra["sink"] = nodes[-1]
                extra["flow_length"] = len(nodes)
            out.append(Finding(
                engine="sast",
                rule_id=query.get("id") or qname,
                title=qname,
                severity=normalize_sev(r.get("Severity") or qsev, SAST_MAP),
                file=r.get("FileName"),
                line=int(r.get("Line")) if (r.get("Line") or "").isdigit() else None,
                description=f"{qname} — data flow of {len(nodes)} node(s)" if nodes else qname,
                extra=extra,
            ))
    return out
