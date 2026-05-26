"""
Unit tests for core scanning functionality.
"""
import ipaddress
import pytest
from unittest.mock import patch, MagicMock

from scanner.core.scanner import (
    scan_tcp_port,
    validate_ip_address,
    parse_ports,
    scan_ports
)


def test_validate_ip_address_valid_ipv4():
    """Test validation of valid IPv4 addresses."""
    assert validate_ip_address("127.0.0.1") == "127.0.0.1"
    assert validate_ip_address("192.168.1.1") == "192.168.1.1"
    assert validate_ip_address("0.0.0.0") == "0.0.0.0"
    assert validate_ip_address("255.255.255.255") == "255.255.255.255"


def test_validate_ip_address_valid_ipv6():
    """Test validation of valid IPv6 addresses."""
    assert validate_ip_address("::1") == "::1"
    assert validate_ip_address("2001:db8::1") == "2001:db8::1"


def test_validate_ip_address_valid_hostname():
    """Test validation of valid hostnames."""
    assert validate_ip_address("localhost") == "localhost"
    assert validate_ip_address("example.com") == "example.com"
    assert validate_ip_address("sub.domain.example.com") == "sub.domain.example.com"


def test_validate_ip_address_invalid():
    """Test validation rejects invalid inputs."""
    with pytest.raises(ValueError):
        validate_ip_address("")  # Empty string

    with pytest.raises(ValueError):
        validate_ip_address("invalid..hostname")  # Double dots

    with pytest.raises(ValueError):
        validate_ip_address("host!invalid")  # Invalid character

    with pytest.raises(ValueError):
        validate_ip_address("a" * 256)  # Too long


def test_parse_ports_single():
    """Test parsing single port specifications."""
    assert parse_ports("80") == [80]
    assert parse_ports("443") == [443]
    assert parse_ports("65535") == [65535]


def test_parse_ports_list():
    """Test parsing comma-separated port lists."""
    assert parse_ports("80,443,8080") == [80, 443, 8080]
    assert parse_ports("80, 443 , 8080 ") == [80, 443, 8080]  # With spaces


def test_parse_ports_range():
    """Test parsing port ranges."""
    assert parse_ports("1-10") == list(range(1, 11))
    assert parse_ports("100-105") == [100, 101, 102, 103, 104, 105]


def test_parse_ports_mixed():
    """Test parsing mixed specifications."""
    assert parse_ports("80,443,8000-8010") == [80, 443] + list(range(8000, 8011))


def test_parse_ports_invalid():
    """Test parsing rejects invalid specifications."""
    with pytest.raises(ValueError):
        parse_ports("")  # Empty

    with pytest.raises(ValueError):
        parse_ports("99999")  # Port too high

    with pytest.raises(ValueError):
        parse_ports("0")  # Port too low

    with pytest.raises(ValueError):
        parse_ports("80,99999")  # Mixed valid/invalid

    with pytest.raises(ValueError):
        parse_ports("abc")  # Non-numeric

    with pytest.raises(ValueError):
        parse_ports("10-5")  # Invalid range (start > end)


@patch('socket.socket')
def test_scan_tcp_port_open(mock_socket):
    """Test scan_tcp_port returns True when port is open."""
    mock_instance = MagicMock()
    mock_instance.connect_ex.return_value = 0
    mock_socket.return_value.__enter__.return_value = mock_instance

    result = scan_tcp_port('localhost', 80)
    assert result is True


@patch('socket.socket')
def test_scan_tcp_port_closed(mock_socket):
    """Test scan_tcp_port returns False when port is closed."""
    mock_instance = MagicMock()
    mock_instance.connect_ex.return_value = 1  # Connection refused
    mock_socket.return_value.__enter__.return_value = mock_instance

    result = scan_tcp_port('localhost', 81)
    assert result is False


@patch('socket.socket')
def test_scan_tcp_port_timeout(mock_socket):
    """Test scan_tcp_port handles timeout (returns False)."""
    mock_instance = MagicMock()
    mock_instance.connect_ex.return_value = 110  # Connection timed out
    mock_socket.return_value.__enter__.return_value = mock_instance

    result = scan_tcp_port('localhost', 82)
    assert result is False


@patch('socket.socket')
@patch('scanner.core.scanner.validate_ip_address')
def test_scan_ports_basic(mock_validate, mock_socket):
    """Test scan_ports with basic functionality."""
    # Mock validation to return host unchanged
    mock_validate.return_value = '127.0.0.1'

    # Mock socket responses: port 80 open, 81 closed
    def connect_ex_side_effect(address):
        host, port = address
        if port == 80:
            return 0  # Open
        return 1  # Closed

    mock_instance = MagicMock()
    mock_instance.connect_ex.side_effect = connect_ex_side_effect
    mock_socket.return_value.__enter__.return_value = mock_instance

    open_ports = scan_ports('localhost', [80, 81], timeout=0.5, max_threads=2)
    assert open_ports == [80]


@patch('scanner.core.scanner.validate_ip_address')
def test_scan_ports_invalid_host(mock_validate):
    """Test scan_ports handles invalid host."""
    mock_validate.side_effect = ValueError("Invalid host")

    with pytest.raises(ValueError, match="Invalid host"):
        scan_ports('invalid!!host', [80, 443])