"""Integration tests using real local TCP sockets."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from scanner.cli.main import app
from scanner.core.scanner import scan_tcp_port, scan_tcp_port_with_banner

pytestmark = pytest.mark.integration


def test_scan_tcp_port_detects_real_open_port(local_tcp_server) -> None:
    assert scan_tcp_port("127.0.0.1", local_tcp_server.endpoint.port, timeout=1.0) is True


def test_scan_tcp_port_detects_real_closed_port(unused_local_port: int) -> None:
    assert scan_tcp_port("127.0.0.1", unused_local_port, timeout=0.2) is False


def test_scan_tcp_port_with_banner_reads_real_banner(local_banner_server) -> None:
    is_open, banner = scan_tcp_port_with_banner(
        "127.0.0.1",
        local_banner_server.endpoint.port,
        timeout=1.0,
    )

    assert is_open is True
    assert banner == "SSH-2.0-TestServer\r\n"


def test_cli_json_report_against_real_local_server(local_tcp_server) -> None:
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
            "--json-output",
        ],
    )

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["target"] == "127.0.0.1"
    assert report["open_ports_count"] == 1
    assert report["open_ports"][0]["port"] == local_tcp_server.endpoint.port
