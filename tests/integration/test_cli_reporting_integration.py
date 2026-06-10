"""End-to-end CLI report generation against local services."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from scanner.cli.main import app

pytestmark = pytest.mark.integration


def test_cli_writes_exploitable_json_report(local_tcp_server, tmp_path) -> None:
    output_file = tmp_path / "scan.json"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "--host",
            "127.0.0.1",
            "--ports",
            str(local_tcp_server.endpoint.port),
            "--timeout",
            "1.0",
            "--threads",
            "1",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["target"] == "127.0.0.1"
    assert report["open_ports_count"] == 1
    assert report["open_ports"][0]["port"] == local_tcp_server.endpoint.port
    assert "risk" in report["open_ports"][0]


def test_cli_writes_exploitable_html_report(local_banner_server, tmp_path) -> None:
    output_file = tmp_path / "scan.html"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "scan",
            "--host",
            "127.0.0.1",
            "--ports",
            str(local_banner_server.endpoint.port),
            "--timeout",
            "1.0",
            "--threads",
            "1",
            "--banner-grab",
            "--format",
            "html",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    html = output_file.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "TCP Scan Report - 127.0.0.1" in html
    assert str(local_banner_server.endpoint.port) in html
    assert "SSH-2.0-TestServer" in html
