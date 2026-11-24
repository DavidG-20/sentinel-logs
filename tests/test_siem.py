"""Unit and integration tests for sentinel-logs Mini-SIEM engine and SOC web API."""

from pathlib import Path

from fastapi.testclient import TestClient

from sentinel_logs.engine import analyze_log_text, export_alerts_csv
from sentinel_logs.web import app

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


def test_nginx_sample_detects_sqli_xss_traversal_subnet_and_spike() -> None:
    text = (SAMPLES_DIR / "sample_nginx.log").read_text(encoding="utf-8")
    report = analyze_log_text(text)

    rule_ids = {a.rule_id for a in report.alerts}
    assert "WEB-SQLI-001" in rule_ids
    assert "WEB-XSS-002" in rule_ids
    assert "WEB-TRAVERSAL-003" in rule_ids
    assert "WEB-SCAN-004" in rule_ids
    assert "NET-SUBNET-001" in rule_ids
    assert "ANOM-SPIKE-001" in rule_ids
    assert report.high_count >= 4


def test_ssh_sample_detects_bruteforce_and_coordinated_subnet() -> None:
    text = (SAMPLES_DIR / "sample_ssh.log").read_text(encoding="utf-8")
    report = analyze_log_text(text)

    brute_alerts = [a for a in report.alerts if a.rule_id == "SSH-BRUTE-001"]
    assert len(brute_alerts) == 2
    assert any(a.rule_id == "NET-SUBNET-001" and a.subnet_24 == "203.0.113.0/24" for a in report.alerts)


def test_csv_export_sanitizes_formula_injection() -> None:
    report = analyze_log_text('203.0.113.9 - - "GET /.env HTTP/1.1" 404')
    csv_out = export_alerts_csv(report)
    assert "WEB-SCAN-004" in csv_out
    assert "203.0.113.0/24" in csv_out


def test_web_api_and_security_headers() -> None:
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.headers["x-frame-options"] == "DENY"
    assert health.headers["x-content-type-options"] == "nosniff"

    sample = client.get("/api/v1/samples/nginx")
    assert sample.status_code == 200

    analyzed = client.post("/api/v1/analyze", json={"log_text": sample.json()["log_text"]})
    assert analyzed.status_code == 200
    assert analyzed.json()["high_count"] >= 4

    csv_resp = client.post("/api/v1/analyze/csv", json={"log_text": sample.json()["log_text"]})
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
