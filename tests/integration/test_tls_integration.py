"""Integration tests using a real local TLS server when certificate tooling exists."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from scanner.cli.main import app
from scanner.core.scanner import scan_tcp_port
from scanner.security import inspect_tls_certificate

pytestmark = pytest.mark.integration


def test_scan_tcp_port_detects_real_tls_server(local_tls_server) -> None:
    assert scan_tcp_port("127.0.0.1", local_tls_server.endpoint.port, timeout=1.0) is True


def test_tls_certificate_inspection_reads_local_certificate(local_tls_server) -> None:
    certificate = inspect_tls_certificate(
        "127.0.0.1",
        local_tls_server.endpoint.port,
        timeout=1.0,
    )

    assert certificate is not None
    assert "localhost" in certificate.subject
    assert "127.0.0.1" in certificate.san


def test_cli_json_report_with_real_tls_inspection(local_tls_server) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "--host",
            "127.0.0.1",
            "--ports",
            str(local_tls_server.endpoint.port),
            "--timeout",
            "1.0",
            "--threads",
            "1",
            "--tls-inspect",
            "--json-output",
        ],
    )

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["open_ports_count"] == 1
    finding = report["open_ports"][0]
    assert finding["port"] == local_tls_server.endpoint.port
    assert finding["tls"] is True
    assert finding["tls_certificate"] is not None
    assert "localhost" in finding["tls_certificate"]["subject"]
