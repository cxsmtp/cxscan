"""Parser tests — the riskiest surface, since vendor report shapes drift."""
from app import normalize


def test_parse_kics_sarif_severity_from_properties(fixtures):
    findings = normalize.parse_sarif(fixtures / "kics.sarif", "kics")
    assert len(findings) == 2
    high = next(f for f in findings if f.rule_id == "a1b2")
    assert high.severity == "HIGH"            # from properties.severity, not level
    assert high.title == "Privileged container"
    assert high.file == "deploy/pod.yaml" and high.line == 12
    assert "remediation" in high.extra        # pulled from rule help text
    info = next(f for f in findings if f.rule_id == "unknown-rule")
    assert info.severity == "INFO"


def test_parse_2ms_sarif_redacts_secret_values(fixtures):
    findings = normalize.parse_sarif(fixtures / "2ms.sarif", "twoms")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "HIGH"               # SARIF level "error" -> HIGH
    assert f.file == "config/prod.env" and f.line == 7
    pub = f.public(redact=True)               # the secret must never reach the UI
    assert "secret" not in pub["extra"] and "match" not in pub["extra"]
    assert "secret" in f.extra                # but the raw finding still has it in memory


def test_parse_sca_cxone_cli_shape(fixtures):
    findings = normalize.parse_sca_json(fixtures / "sca_cxone.json")
    assert len(findings) == 1                 # the non-sca result is filtered out
    f = findings[0]
    assert f.severity == "CRITICAL"
    assert f.rule_id == "CVE-2021-44228"
    assert f.extra["package"] == "log4j-core" and f.extra["version"] == "2.14.1"
    assert f.extra["fixed_version"] == "2.17.1"
    assert f.extra["cvss"] == 10.0
    assert f.extra["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]


def test_parse_sca_resolver_shape(fixtures):
    findings = normalize.parse_sca_json(fixtures / "sca_resolver.json")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MEDIUM"
    assert f.rule_id == "CVE-2018-18074"
    assert f.extra["fixed_version"] == "2.20.0"


def test_parse_sast_xml_dataflow(fixtures):
    findings = normalize.parse_sast_xml(fixtures / "sast.xml")
    assert len(findings) == 2
    sqli = next(f for f in findings if f.title == "SQL_Injection")
    assert sqli.severity == "HIGH"
    assert sqli.file == "src/db.java" and sqli.line == 42
    assert sqli.extra["flow_length"] == 2
    assert sqli.extra["source"]["name"] == "getParameter"
    assert sqli.extra["sink"]["name"] == "executeQuery"


def test_parse_sast_json_roundtrips_unified_findings(fixtures, tmp_path):
    # The REST flow writes a unified sast.json; parse_sast_json must read it back.
    src = normalize.parse_sast_xml(fixtures / "sast.xml")
    import json
    p = tmp_path / "sast.json"
    p.write_text(json.dumps([f.public(redact=False) for f in src]))
    back = normalize.parse_sast_json(p)
    assert [f.title for f in back] == [f.title for f in src]
    assert [f.severity for f in back] == [f.severity for f in src]


def test_parse_sast_json_raw_odata_shape(fixtures):
    findings = normalize.parse_sast_json(fixtures / "sast_odata.json")
    assert len(findings) == 2
    sqli = next(f for f in findings if f.title == "SQL_Injection")
    assert sqli.severity == "HIGH"            # integer severity 3 -> HIGH
    assert sqli.file == "src/db.java" and sqli.line == 42
