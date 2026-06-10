"""
Unit tests for core scanning functionality.
"""
from unittest.mock import patch, MagicMock

import pytest

from scanner.core.scanner import (
    _connect,
    _decode_and_truncate_banner,
    _grab_banner,
    parse_ports,
    scan_ports_with_banner,
    scan_tcp_port,
    scan_ports,
    validate_max_threads,
    validate_port,
    validate_ports,
    validate_timeout,
    validate_ip_address,
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

    with pytest.raises(ValueError):
        validate_ip_address("-example.com")  # Invalid label boundary

    with pytest.raises(ValueError):
        validate_ip_address("example-.com")  # Invalid label boundary


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

    with pytest.raises(ValueError):
        parse_ports("1-a")  # Invalid range format


@patch('scanner.core.scanner._connect')
def test_scan_tcp_port_open(mock_connect):
    """Test scan_tcp_port returns True when port is open."""
    mock_connect.return_value.__enter__.return_value = MagicMock()

    result = scan_tcp_port('localhost', 80)
    assert result is True


@patch('scanner.core.scanner._connect')
def test_scan_tcp_port_closed(mock_connect):
    """Test scan_tcp_port returns False when port is closed."""
    mock_connect.side_effect = ConnectionRefusedError("Connection refused")

    result = scan_tcp_port('localhost', 81)
    assert result is False


@patch('scanner.core.scanner._connect')
def test_scan_tcp_port_timeout(mock_connect):
    """Test scan_tcp_port handles timeout (returns False)."""
    mock_connect.side_effect = TimeoutError("Connection timed out")

    result = scan_tcp_port('localhost', 82)
    assert result is False


@patch('scanner.core.scanner._connect')
@patch('scanner.core.scanner.validate_ip_address')
def test_scan_ports_basic(mock_validate, mock_connect):
    """Test scan_ports with basic functionality."""
    # Mock validation to return host unchanged
    mock_validate.return_value = '127.0.0.1'

    def connect_side_effect(host, port, timeout):
        if port == 80:
            return MagicMock()
        raise ConnectionRefusedError("Connection refused")

    mock_connect.side_effect = connect_side_effect
    open_ports = scan_ports('localhost', [80, 81], timeout=0.5, max_threads=2)
    assert open_ports == [80]


@patch('scanner.core.scanner.validate_ip_address')
def test_scan_ports_invalid_host(mock_validate):
    """Test scan_ports handles invalid host."""
    mock_validate.side_effect = ValueError("Invalid host")

    with pytest.raises(ValueError, match="Invalid host"):
        scan_ports('invalid!!host', [80, 443])


def test_validate_helpers_reject_invalid_values():
    with pytest.raises(ValueError):
        validate_port(True)
    with pytest.raises(ValueError):
        validate_timeout(31.0)
    with pytest.raises(ValueError):
        validate_max_threads(False)
    with pytest.raises(ValueError):
        validate_ports([80, 70000])

    assert validate_ports([]) == []


@patch("scanner.core.scanner.socket.create_connection")
def test_connect_uses_socket_create_connection(mock_create_connection):
    mock_create_connection.return_value = MagicMock()

    assert _connect("localhost", 80, 0.5) is mock_create_connection.return_value
    mock_create_connection.assert_called_once_with(("localhost", 80), timeout=0.5)


def test_decode_and_truncate_banner_short_max_length():
    assert _decode_and_truncate_banner(b"abcdef", max_length=3) == "abcdef"


def test_grab_banner_redis_send_error():
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [b"", b""]
    mock_sock.sendall.side_effect = OSError("reset")

    assert _grab_banner(mock_sock, 6379, 1.0) is None


def test_grab_banner_inner_socket_error():
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = OSError("reset")

    assert _grab_banner(mock_sock, 80, 1.0) is None


def test_grab_banner_outer_socket_error():
    mock_sock = MagicMock()
    mock_sock.settimeout.side_effect = OSError("reset")

    assert _grab_banner(mock_sock, 80, 1.0) is None


def test_grab_banner_passive_service_ports():
    for port in [21, 22, 25, 110, 143, 3306, 5432, 27017]:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"banner", b""]

        assert _grab_banner(mock_sock, port, 1.0) == "banner"


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.scan_tcp_port_with_banner')
def test_scan_ports_with_banner(mock_scan_with_banner, mock_validate):
    mock_validate.return_value = "127.0.0.1"

    def side_effect(host, port, timeout):
        if port == 443:
            return True, "TLS service"
        return False, None

    mock_scan_with_banner.side_effect = side_effect

    results = scan_ports_with_banner("localhost", [80, 443], timeout=0.5, max_threads=2)

    assert results == [
        {
            "port": 443,
            "status": "open",
            "service": "HTTPS",
            "banner": "TLS service",
        }
    ]
