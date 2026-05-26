"""
Unit tests for CLI functionality.
"""
import json
import logging
from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from scanner.cli.main import app, show_banner

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
        assert data["open_ports"] == [{"port": 80, "service": "HTTP"}]
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
    assert data["open_ports"] == [{"port": 80, "service": "HTTP"}]
    assert data["open_ports_count"] == 1


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
    mock_logger = mock_get_logger.return_value

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
    mock_logger = mock_get_logger.return_value

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