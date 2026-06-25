"""Gate evaluation, severity normalization, and ${ENV} resolution."""
import os

from app.models import (EngineThreshold, Finding, normalize_sev, resolve_env,
                        SAST_MAP)


def _f(sev):
    return Finding(engine="sast", rule_id="x", title="x", severity=sev)


def test_gate_fails_when_floor_exceeded():
    th = EngineThreshold.from_config({"High": 0, "Medium": 2})
    findings = [_f("HIGH"), _f("MEDIUM"), _f("MEDIUM")]
    passed, reasons = th.evaluate(findings)
    assert passed is False
    # 1 finding >= HIGH (limit 0) and 3 findings >= MEDIUM (limit 2) both fail.
    assert any("HIGH" in r for r in reasons)
    assert any("MEDIUM" in r for r in reasons)


def test_gate_passes_within_limits():
    th = EngineThreshold.from_config({"High": 1, "Medium": 5})
    passed, reasons = th.evaluate([_f("HIGH"), _f("LOW")])
    assert passed is True and reasons == []


def test_gate_counts_are_cumulative_at_or_above():
    # A CRITICAL counts toward the HIGH floor too.
    th = EngineThreshold.from_config({"High": 0})
    passed, _ = th.evaluate([_f("CRITICAL")])
    assert passed is False


def test_threshold_ignores_unknown_severity_keys():
    th = EngineThreshold.from_config({"Bogus": 3, "High": 1})
    assert "HIGH" in th.limits and "BOGUS" not in th.limits


def test_normalize_sev_defaults_to_medium():
    assert normalize_sev("nonsense", SAST_MAP) == "MEDIUM"
    assert normalize_sev("High", SAST_MAP) == "HIGH"
    assert normalize_sev(None, SAST_MAP) == "MEDIUM"


def test_resolve_env_substitutes_recursively():
    os.environ["CXSCAN_TEST_TOKEN"] = "s3cr3t"
    out = resolve_env({"a": "${CXSCAN_TEST_TOKEN}", "b": ["${CXSCAN_TEST_TOKEN}", 1]})
    assert out["a"] == "s3cr3t" and out["b"][0] == "s3cr3t" and out["b"][1] == 1


def test_resolve_env_missing_var_becomes_empty():
    assert resolve_env("${DEFINITELY_NOT_SET_XYZ}") == ""
