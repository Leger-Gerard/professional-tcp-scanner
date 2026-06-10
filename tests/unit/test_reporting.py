"""Unit tests for report models and serializers."""

from datetime import datetime

from scanner.models import PortFinding, ScanReport, score_port_risk
from scanner.policies import get_policy
from scanner.reporting import serialize_report


def _sample_report() -> ScanReport:
    return ScanReport(
        target="127.0.0.1",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=1.25,
        total_ports_scanned=2,
        findings=[
            PortFinding(
                port=80,
                status="open",
                service="HTTP",
                banner="Apache",
                risk="medium",
                risk_score=50,
            )
        ],
        profile="normal",
    )


def test_score_port_risk_high_for_database_ports():
    risk, score, notes = score_port_risk(6379, "Redis")

    assert risk == "high"
    assert score >= 70
    assert notes


def test_score_port_risk_low_for_unknown_port():
    risk, score, notes = score_port_risk(12345, "unknown")

    assert risk == "low"
    assert score == 20
    assert notes == []


def test_score_port_risk_banner_signal_and_tls_http():
    risk, score, notes = score_port_risk(
        80,
        "HTTP",
        banner="default unauthorized",
        tls=True,
    )

    assert risk == "medium"
    assert score == 55
    assert "banner contains potentially sensitive security signal" in notes


def test_score_port_risk_telnet_extra_note():
    risk, score, notes = score_port_risk(23, "Telnet")

    assert risk == "high"
    assert score == 90
    assert "cleartext remote administration" in notes


def test_scan_policy_clamps_parameters():
    policy = get_policy("safe")
    ports, timeout, threads = policy.apply([80, 443], timeout=0.1, threads=100)

    assert ports == [80, 443]
    assert timeout == 1.0
    assert threads == 25


def test_scan_policy_limits_port_count():
    policy = get_policy("safe")

    try:
        policy.apply(list(range(1, 1026)), timeout=1.0, threads=10)
    except ValueError as exc:
        assert "allows at most" in str(exc)
    else:
        raise AssertionError("Expected port count limit to be enforced")


def test_json_report_serialization():
    report = _sample_report()
    output = serialize_report(report, "json")

    assert '"target": "127.0.0.1"' in output
    assert '"highest_risk": "medium"' in output


def test_csv_report_serialization():
    report = _sample_report()
    output = serialize_report(report, "csv")

    assert "port,status,service,risk,risk_score,tls,banner" in output
    assert "80,open,HTTP,medium,50,False,Apache" in output


def test_markdown_report_serialization():
    report = _sample_report()
    output = serialize_report(report, "markdown")

    assert "# TCP Scan Report: 127.0.0.1" in output
    assert "| 80 | HTTP | medium | 50 | False | Apache |" in output


def test_html_report_serialization_escapes_banner():
    report = ScanReport(
        target="example.com",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=1.0,
        total_ports_scanned=1,
        findings=[
            PortFinding(
                port=80,
                status="open",
                service="HTTP",
                banner="<script>alert(1)</script>",
            )
        ],
        profile="normal",
    )
    output = serialize_report(report, "html")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "<script>alert(1)</script>" not in output


def test_unsupported_report_format():
    report = _sample_report()

    try:
        serialize_report(report, "xml")
    except ValueError as exc:
        assert "Unsupported report format" in str(exc)
    else:
        raise AssertionError("Expected unsupported report format to raise")
