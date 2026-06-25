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


# ---- SCA (Resolver risk-report JSON) ----------------------------------------
def parse_sca_json(path: Path) -> list[Finding]:
    """ADAPTER — verify against a real Resolver --report-type json output."""
    data = _load_json(path)
    out: list[Finding] = []
    vulns = data.get("Vulnerabilities") or data.get("vulnerabilities") or []
    for v in vulns:
        pkg = v.get("PackageName") or v.get("packageName") or ""
        ver = v.get("PackageVersion") or v.get("version") or ""
        cve = v.get("Cve") or v.get("cveName") or v.get("id") or "SCA"
        fixed = (v.get("RecommendedVersion") or v.get("recommendedVersion")
                 or v.get("fixResolutionText") or v.get("fixedVersion"))
        out.append(Finding(
            engine="sca",
            rule_id=cve,
            title=f"{pkg}@{ver}: {cve}".strip(": "),
            severity=normalize_sev(v.get("Severity") or v.get("severity"), SCA_MAP),
            file=pkg or None,
            description=v.get("Description") or v.get("description") or "",
            extra={"package": pkg, "version": ver,
                   "cve": cve, "fixed_version": fixed,
                   "cvss": v.get("Score") or v.get("cvssScore"),
                   "references": (v.get("References") or v.get("references") or [])[:5]},
        ))
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
