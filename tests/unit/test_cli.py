"""
Unit tests for CLI functionality.
"""
import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest
import typer
from typer.testing import CliRunner

from scanner.cli.main import (
    _NoopProgress,
    _build_json_report,
    _build_scan_report,
    _display_results,
    _scan_with_progress,
    app,
    setup_logging,
    show_banner,
    validate_report_format,
)
from scanner.models import PortFinding, ScanReport, TlsCertificateInfo

runner = CliRunner()


def test_app_help():
    """Test that the app shows help."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Professional TCP port scanner" in result.stdout


def test_scan_help():
    """Test that scan command shows help."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan TCP ports on a target host" in result.stdout


def test_version_command():
    """Test version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "TCP Port Scanner v1.0.0" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_basic(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with basic parameters."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80, 443]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80,443",
        "--timeout", "1.0",
        "--threads", "10"
    ])

    assert result.exit_code == 0
    mock_validate_ip.assert_called_once_with("localhost")
    mock_parse_ports.assert_called_once_with("80,443")
    mock_scan_with_progress.assert_called_once()


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_json_output(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with JSON output."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--json-output"
    ])

    assert result.exit_code == 0
    # Should contain valid JSON - extract JSON from output
    output = result.stdout.strip()
    # Find JSON part (starts with { and ends with })
    json_start = output.find('{')
    json_end = output.rfind('}') + 1
    assert json_start != -1 and json_end != 0, f"No JSON found in output: {output}"
    json_str = output[json_start:json_end]

    try:
        data = json.loads(json_str)
        assert data["target"] == "127.0.0.1"
        assert data["open_ports"][0]["port"] == 80
        assert data["open_ports"][0]["service"] == "HTTP"
        assert data["open_ports"][0]["risk"] == "medium"
        assert data["open_ports_count"] == 1
    except json.JSONDecodeError as e:
        pytest.fail(f"Output is not valid JSON: {json_str}. Error: {e}")


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_json_output_to_file(mock_scan_with_progress, mock_parse_ports, mock_validate_ip, tmp_path):
    """Test scan command with JSON output to file."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    output_file = tmp_path / "scan.json"

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--json-output",
        "--output", str(output_file)
    ])

    assert result.exit_code == 0
    # Check that file was created and contains valid JSON
    assert output_file.exists()
    json_content = output_file.read_text()
    data = json.loads(json_content)
    assert data["target"] == "127.0.0.1"
    assert data["open_ports"][0]["port"] == 80
    assert data["open_ports"][0]["service"] == "HTTP"
    assert data["open_ports"][0]["risk"] == "medium"
    assert data["open_ports_count"] == 1


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_markdown_output(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with Markdown output."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--format", "markdown",
    ])

    assert result.exit_code == 0
    assert "# TCP Scan Report: 127.0.0.1" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_csv_output_to_file(
    mock_scan_with_progress,
    mock_parse_ports,
    mock_validate_ip,
    tmp_path,
):
    """Test scan command with CSV output file."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]
    output_file = tmp_path / "scan.csv"

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--format", "csv",
        "--output", str(output_file),
    ])

    assert result.exit_code == 0
    assert output_file.exists()
    assert "80,open,HTTP" in output_file.read_text()


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_json_output_without_json_flag(mock_scan_with_progress, mock_parse_ports, mock_validate_ip, tmp_path):
    """Test that --output without --json-output is ignored or handled appropriately."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    output_file = tmp_path / "scan.json"

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--output", str(output_file)
    ])

    # Should succeed but not create JSON file since --json-output not specified
    assert result.exit_code == 0
    # File should not be created since we didn't specify --json-output
    assert not output_file.exists()


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
@patch('pathlib.Path.write_text')
def test_scan_command_json_output_permission_error(mock_write_text, mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command handles permission errors when writing JSON output."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]
    mock_write_text.side_effect = PermissionError("Permission denied")

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--json-output",
        "--output", "/protected/system/file.json"
    ])

    # Should fail due to permission error
    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "Failed to write JSON report" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
def test_scan_command_invalid_host(mock_validate_ip):
    """Test scan command with invalid host."""
    mock_validate_ip.side_effect = ValueError("Invalid hostname")

    result = runner.invoke(app, [
        "scan",
        "--host", "invalid!!host",
        "--ports", "80"
    ])

    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "Invalid hostname" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
def test_scan_command_invalid_ports(mock_parse_ports, mock_validate_ip):
    """Test scan command with invalid port specification."""
    mock_validate_ip.return_value = "localhost"
    mock_parse_ports.side_effect = ValueError("Invalid port specification")

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "99999"
    ])

    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "Invalid port specification" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_stealth_mode(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with stealth mode."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80, 443]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80,443",
        "--timeout", "1.0",  # Should be adjusted to 2.0 due to stealth
        "--threads", "100",  # Should be adjusted to 50 due to stealth
        "--stealth"
    ])

    assert result.exit_code == 0
    # Check that stealth mode was referenced (adjusting for rich formatting)
    assert "Stealth mode enabled" in result.stdout
    # Verify the adjusted parameters were passed to _scan_with_progress
    # (We can't easily check the exact values due to mocking, but we know the function was called)


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_verbose_mode(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with verbose mode."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--verbose"
    ])

    assert result.exit_code == 0
    # Verbose mode should work without errors


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_no_banner(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command with banner disabled."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--no-banner"
    ])

    assert result.exit_code == 0
    # Should not contain banner when --no-banner is used
    # The banner is ASCII art, so we check that it's not prominently displayed
    # (This is a bit tricky to test precisely, but at least we ensure it runs)


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_keyboard_interrupt(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command handling keyboard interrupt."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.side_effect = KeyboardInterrupt("Simulated Ctrl+C")

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80"
    ])

    assert result.exit_code == 1
    assert "Scan interrupted by user" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_no_open_ports(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command when no ports are open."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80, 443]
    mock_scan_with_progress.return_value = []  # No open ports

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80,443"
    ])

    assert result.exit_code == 0
    assert "No open ports found on 127.0.0.1" in result.stdout


def test_invalid_timeout_value():
    """Test that invalid timeout values are rejected."""
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--timeout", "0.05"  # Below minimum of 0.1
    ])
    assert result.exit_code != 0  # Should fail validation

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--timeout", "35.0"  # Above maximum of 30.0
    ])
    assert result.exit_code != 0  # Should fail validation


def test_invalid_threads_value():
    """Test that invalid thread values are rejected."""
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--threads", "0"  # Below minimum of 1
    ])
    assert result.exit_code != 0  # Should fail validation

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--threads", "1001"  # Above maximum of 1000
    ])
    assert result.exit_code != 0  # Should fail validation


def test_show_banner():
    """Test the show_banner function."""
    # This test ensures the banner function doesn't crash
    # We can't easily test the Rich output in a unit test without mocking console
    try:
        show_banner()
        assert True  # If we get here, it didn't crash
    except Exception as e:
        pytest.fail(f"show_banner() raised an exception: {e}")


def test_validate_report_format_rejects_unknown_format():
    with pytest.raises(Exception):
        validate_report_format("xml")


def test_setup_logging_with_file(tmp_path):
    log_file = tmp_path / "scanner.log"

    setup_logging(verbose=True, log_file=log_file, quiet_console=True)

    assert log_file.parent.exists()


def test_noop_progress_update():
    progress = _NoopProgress()

    assert progress.update(0, advance=1) is None


@patch("scanner.cli.main.scan_tcp_port")
def test_scan_with_progress_empty_and_exception_paths(mock_scan_tcp):
    progress = Mock()

    assert _scan_with_progress("localhost", [], 0.5, 1, progress, 1) == []

    mock_scan_tcp.side_effect = [True, RuntimeError("boom")]
    result = _scan_with_progress("localhost", [80, 81], 0.5, 2, progress, 1)

    assert result == [80]
    assert progress.update.call_count == 2


@patch("scanner.cli.main.scan_tcp_port_with_banner")
def test_scan_with_progress_banner_exception_paths(mock_scan_with_banner):
    progress = Mock()
    mock_scan_with_banner.side_effect = [
        (True, "HTTP banner"),
        RuntimeError("boom"),
        (False, None),
    ]

    result = _scan_with_progress(
        "localhost",
        [80, 81, 82],
        0.5,
        3,
        progress,
        1,
        grab_banner=True,
    )

    assert result == [
        {
            "port": 80,
            "status": "open",
            "service": "HTTP",
            "banner": "HTTP banner",
        }
    ]
    assert progress.update.call_count == 3


@patch("scanner.cli.main.reverse_dns_lookup")
@patch("scanner.cli.main.inspect_tls_certificate")
def test_build_scan_report_with_banner_tls_and_reverse_dns(mock_tls, mock_reverse_dns):
    mock_tls.return_value = TlsCertificateInfo(
        subject="commonName=localhost",
        issuer="commonName=Test CA",
        not_before="Jan  1 00:00:00 2026 GMT",
        not_after="Jan  1 00:00:00 2027 GMT",
        serial_number="01",
        san=["127.0.0.1"],
    )
    mock_reverse_dns.return_value = "localhost"

    report = _build_scan_report(
        "127.0.0.1",
        [{"port": 443, "status": "open", "service": "HTTPS", "banner": "nginx"}],
        datetime(2026, 1, 1, 12, 0, 0),
        1.0,
        1,
        profile="normal",
        banner_grab=True,
        tls_inspection=True,
        reverse_dns=True,
        timeout=0.5,
    )

    assert report.reverse_dns == "localhost"
    assert report.findings[0].tls is True
    assert report.findings[0].service == "HTTPS"
    mock_tls.assert_called_once_with("127.0.0.1", 443, 0.5)


def test_build_json_report_banner_shape():
    data = _build_json_report(
        "127.0.0.1",
        [{"port": 22, "status": "open", "service": "SSH", "banner": "OpenSSH"}],
        1.0,
        1,
        banner_grab=True,
    )

    assert data["open_ports"][0]["banner"] == "OpenSSH"


def test_display_results_table_no_findings(capsys):
    report = ScanReport(
        target="127.0.0.1",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=0.1,
        total_ports_scanned=1,
        findings=[],
        profile="normal",
    )

    _display_results(report, "table")

    captured = capsys.readouterr()
    assert "No open ports found" in captured.out


def test_display_results_table_long_banner(capsys):
    report = ScanReport(
        target="127.0.0.1",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=0.1,
        total_ports_scanned=1,
        findings=[
            PortFinding(
                port=80,
                status="open",
                service="HTTP",
                banner="A" * 100,
                risk="medium",
                risk_score=50,
            )
        ],
        profile="normal",
    )

    _display_results(report, "table")

    captured = capsys.readouterr()
    assert "HTTP" in captured.out


@patch("pathlib.Path.write_text")
def test_display_results_non_json_write_error(mock_write_text, tmp_path):
    mock_write_text.side_effect = OSError("disk full")
    report = ScanReport(
        target="127.0.0.1",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=0.1,
        total_ports_scanned=1,
        findings=[],
        profile="normal",
    )

    with pytest.raises(typer.Exit):
        _display_results(report, "markdown", tmp_path / "report.md")


@patch('scanner.cli.main.logging.getLogger')
@patch('scanner.cli.main.setup_logging')
@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_logging_setup(mock_scan_with_progress, mock_parse_ports, mock_validate_ip,
                                   mock_setup_logging, mock_get_logger):
    """Test that logging is properly set up."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]


    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80"
    ])

    assert result.exit_code == 0
    # Verify logging setup was called
    mock_setup_logging.assert_called_once()
    # Verify logger was retrieved with correct module name
    mock_get_logger.assert_called_once_with("scanner.cli.main")


@patch('scanner.cli.main.logging.getLogger')
@patch('scanner.cli.main.setup_logging')
@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_verbose_logging(mock_scan_with_progress, mock_parse_ports, mock_validate_ip,
                                      mock_setup_logging, mock_get_logger):
    """Test that verbose logging is enabled."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]


    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--verbose"
    ])

    assert result.exit_code == 0
    # Verify logging setup was called with verbose=True
    mock_setup_logging.assert_called_once()
    args, kwargs = mock_setup_logging.call_args
    assert args[0] is True  # verbose parameter should be True


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_normal_mode_open_port(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test scan command in normal mode (no banner grab) with open port."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]  # Simulate port 80 open

    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80"
    ])

    assert result.exit_code == 0
    # Verify the mocked function was called with correct parameters
    mock_validate_ip.assert_called_once_with("localhost")
    mock_parse_ports.assert_called_once_with("80")
    mock_scan_with_progress.assert_called_once()
    # Verify that open port is displayed in output
    assert "80" in result.stdout
    assert "HTTP" in result.stdout  # Service detection for port 80
