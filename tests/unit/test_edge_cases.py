"""
Edge case tests to improve coverage.
"""
import ipaddress
import socket
from unittest.mock import patch, MagicMock
import pytest

from scanner.core.scanner import (
    scan_tcp_port,
    validate_ip_address,
    parse_ports,
    scan_ports
)
from scanner.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_validate_ip_address_edge_cases():
    """Test edge cases in hostname validation."""
    # Test empty string
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("")

    # Test string with only dots
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("...")

    # Test string starting with dot
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address(".example.com")

    # Test string ending with dot
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("example.com.")

    # Test string with consecutive dots
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("ex..ample.com")

    # Test string with no alphanumeric characters
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("---")

    # Test string with only dots and hyphens
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address("-.-")

    # Test very long hostname (>255 chars)
    long_host = "a" * 256
    with pytest.raises(ValueError, match="Invalid hostname"):
        validate_ip_address(long_host)

    # Test valid hostname at exactly 255 chars
    valid_long_host = "a" * 255
    assert validate_ip_address(valid_long_host) == valid_long_host


def test_parse_ports_edge_cases():
    """Test edge cases in port parsing."""
    # Test whitespace handling
    assert parse_ports(" 80 ") == [80]
    assert parse_ports(" 80 , 443 ") == [80, 443]
    assert parse_ports(" 1-10 ") == list(range(1, 11))

    # Test mixed whitespace and delimiters
    assert parse_ports("80 ,443, 8080") == [80, 443, 8080]
    assert parse_ports(" 1 - 10 ") == list(range(1, 11))

    # Test invalid port values that should raise ValueError
    with pytest.raises(ValueError):
        parse_ports("99999")  # Port too high

    with pytest.raises(ValueError):
        parse_ports("0")  # Port too low

    with pytest.raises(ValueError):
        parse_ports("-1")  # Negative port

    with pytest.raises(ValueError):
        parse_ports("80,99999")  # Mixed valid/invalid

    with pytest.raises(ValueError):
        parse_ports("80,abc")  # Non-numeric

    with pytest.raises(ValueError):
        parse_ports("abc,80")  # Non-numeric first

    with pytest.raises(ValueError):
        parse_ports("10-5")  # Invalid range (start > end)

    with pytest.raises(ValueError):
        parse_ports("10-")  # Incomplete range

    with pytest.raises(ValueError):
        parse_ports("-10")  # Incomplete range

    with pytest.raises(ValueError):
        parse_ports("10-a")  # Non-numeric in range

    with pytest.raises(ValueError):
        parse_ports("a-10")  # Non-numeric in range

    with pytest.raises(ValueError):
        parse_ports("")  # Empty string

    with pytest.raises(ValueError):
        parse_ports(",")  # Just comma

    with pytest.raises(ValueError):
        parse_ports("80,")  # Trailing comma

    with pytest.raises(ValueError):
        parse_ports(",80")  # Leading comma

    with pytest.raises(ValueError):
        parse_ports("80,,443")  # Double comma


@patch('socket.socket')
def test_scan_tcp_port_exceptions(mock_socket):
    """Test exception handling in scan_tcp_port."""
    # Test socket.gaierror (DNS resolution failure)
    mock_socket.side_effect = socket.gaierror("Name or service not known")
    result = scan_tcp_port("invalidhostname", 80)
    assert result is False

    # Test socket.error (generic socket error)
    mock_socket.side_effect = socket.error("Network error")
    result = scan_tcp_port("127.0.0.1", 80)
    assert result is False

    # Test generic Exception
    mock_socket.side_effect = Exception("Unexpected error")
    result = scan_tcp_port("127.0.0.1", 80)
    assert result is False

    # Test successful case
    mock_instance = MagicMock()
    mock_instance.connect_ex.return_value = 0
    mock_socket.return_value.__enter__.return_value = mock_instance
    mock_socket.side_effect = None  # Reset side effect

    result = scan_tcp_port("localhost", 80)
    assert result is True

    # Test closed port
    mock_instance.connect_ex.return_value = 1  # Connection refused
    result = scan_tcp_port("localhost", 81)
    assert result is False

    # Test timeout (return code 110 on Linux)
    mock_instance.connect_ex.return_value = 110
    result = scan_tcp_port("localhost", 82)
    assert result is False


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.socket.socket')
def test_scan_ports_exceptions(mock_socket, mock_validate):
    """Test exception handling in scan_ports."""
    # Setup validation mock
    mock_validate.return_value = "127.0.0.1"

    # Test that invalid host raises ValueError
    mock_validate.side_effect = ValueError("Invalid host")
    with pytest.raises(ValueError, match="Invalid host"):
        scan_ports("invalid!!host", [80, 443])

    # Reset validation mock
    mock_validate.side_effect = None
    mock_validate.return_value = "127.0.0.1"

    # Test socket exceptions during scanning
    mock_instance = MagicMock()
    mock_instance.connect_ex.side_effect = socket.error("Network error")
    mock_socket.return_value.__enter__.return_value = mock_instance

    # Should handle the error gracefully and return empty list
    result = scan_ports("localhost", [80, 443], max_threads=2)
    assert result == []  # No ports should be open due to errors

    # Test mixed success and failure
    def connect_ex_side_effect(address):
        host, port = address
        if port == 80:
            return 0  # Open
        elif port == 81:
            raise socket.error("Network error")  # Error
        else:
            return 1  # Closed

    mock_instance.connect_ex.side_effect = connect_ex_side_effect
    result = scan_ports("localhost", [80, 81, 82], max_threads=3)
    assert result == [80]  # Only port 80 should be open


@patch('scanner.core.scanner.validate_ip_address')
def test_scan_ports_empty_list(mock_validate):
    """Test scan_ports with empty port list."""
    mock_validate.return_value = "localhost"
    result = scan_ports("localhost", [], max_threads=10)
    assert result == []


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.scan_tcp_port')
def test_scan_ports_single_port(mock_scan_tcp, mock_validate):
    """Test scan_ports with single port."""
    mock_validate.return_value = "localhost"
    mock_scan_tcp.return_value = True

    result = scan_ports("localhost", [80], max_threads=1)
    assert result == [80]
    mock_scan_tcp.assert_called_once_with("localhost", 80, 0.5)


def test_scan_command_main_entry_point():
    """Test the main entry point of the application."""
    # Test that the app can be invoked as a module
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Professional TCP port scanner" in result.stdout

    # Test version command through main entry point
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "TCP Port Scanner v1.0.0" in result.stdout


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_timeout_validation(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test timeout validation in scan command."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    # Test valid timeout values
    for timeout in [0.1, 1.0, 15.0, 30.0]:
        result = runner.invoke(app, [
            "scan",
            "--host", "localhost",
            "--ports", "80",
            "--timeout", str(timeout)
        ])
        assert result.exit_code == 0

    # Test invalid timeout values (below minimum)
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--timeout", "0.05"
    ])
    assert result.exit_code != 0

    # Test invalid timeout values (above maximum)
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--timeout", "35.0"
    ])
    assert result.exit_code != 0


@patch('scanner.cli.main.validate_ip_address')
@patch('scanner.cli.main.parse_ports')
@patch('scanner.cli.main._scan_with_progress')
def test_scan_command_threads_validation(mock_scan_with_progress, mock_parse_ports, mock_validate_ip):
    """Test threads validation in scan command."""
    # Setup mocks
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]
    mock_scan_with_progress.return_value = [80]

    # Test valid thread values
    for threads in [1, 50, 100, 500, 1000]:
        result = runner.invoke(app, [
            "scan",
            "--host", "localhost",
            "--ports", "80",
            "--threads", str(threads)
        ])
        assert result.exit_code == 0

    # Test invalid thread values (below minimum)
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--threads", "0"
    ])
    assert result.exit_code != 0

    # Test invalid thread values (above maximum)
    result = runner.invoke(app, [
        "scan",
        "--host", "localhost",
        "--ports", "80",
        "--threads", "1001"
    ])
    assert result.exit_code != 0