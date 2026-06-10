"""
Unit tests for banner grabbing functionality.
"""
import socket
from unittest.mock import Mock, patch

from scanner.core.scanner import (
    _grab_banner,
    scan_tcp_port,
    scan_tcp_port_with_banner
)


def test_grab_banner_no_data():
    """Test _grab_banner when no data is received."""
    mock_sock = Mock()
    mock_sock.recv.side_effect = socket.timeout("timeout")

    result = _grab_banner(mock_sock, 80, 1.0)
    assert result is None


def test_grab_banner_with_data():
    """Test _grab_banner when data is received."""
    mock_sock = Mock()
    # Simulate receiving data immediately (no need to send probe)
    # First recv gets the data, second recv times out
    mock_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nServer: test", b""]
    # Mock send to do nothing (in case probe is sent)
    mock_sock.send.return_value = None

    result = _grab_banner(mock_sock, 80, 1.0)
    # Should get the data from the first recv
    assert result == "HTTP/1.1 200 OK\r\nServer: test"


def test_grab_banner_empty_data():
    """Test _grab_banner when empty data is received."""
    mock_sock = Mock()
    mock_sock.recv.return_value = b""

    result = _grab_banner(mock_sock, 80, 1.0)
    assert result is None


def test_grab_banner_http_probe():
    """Test _grab_banner sends HTTP probe for HTTP ports."""
    mock_sock = Mock()
    mock_sock.recv.return_value = b""  # No initial data

    with patch('scanner.core.scanner.socket.socket') as mock_socket_class:
        mock_socket_instance = Mock()
        mock_socket_class.return_value.__enter__.return_value = mock_socket_instance
        mock_socket_instance.recv.return_value = b""

    _ = _grab_banner(mock_socket_instance, 80, 1.0)
    # Check that send was called for HTTP probe
    mock_socket_instance.sendall.assert_called()


def test_grab_banner_length_limit():
    """Test _grab_banner limits banner length."""
    mock_sock = Mock()
    long_data = b"A" * 600
    mock_sock.recv.return_value = long_data

    result = _grab_banner(mock_sock, 80, 1.0)
    assert result is not None
    # Limit banner to approximately 500 characters plus truncation marker
    assert len(result) <= 512
    if len(result) > 500:
        assert "[truncated]" in result


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.parse_ports')
def test_scan_tcp_port_with_banner_closed_port(mock_parse_ports, mock_validate_ip):
    """Test scan_tcp_port_with_banner with closed port."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]

    with patch('scanner.core.scanner._connect') as mock_connect:
        mock_connect.side_effect = ConnectionRefusedError("Connection refused")

        is_open, banner = scan_tcp_port_with_banner("127.0.0.1", 80, 0.5)

        assert is_open is False
        assert banner is None


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.parse_ports')
def test_scan_tcp_port_with_banner_open_port_no_banner(mock_parse_ports, mock_validate_ip):
    """Test scan_tcp_port_with_banner with open port but no banner."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]

    with patch('scanner.core.scanner._connect') as mock_connect:
        mock_socket_instance = Mock()
        mock_connect.return_value.__enter__.return_value = mock_socket_instance
        mock_socket_instance.recv.return_value = b""  # No banner data

        is_open, banner = scan_tcp_port_with_banner("127.0.0.1", 80, 0.5)

        assert is_open is True
        assert banner is None


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.parse_ports')
def test_scan_tcp_port_with_banner_open_port_with_banner(mock_parse_ports, mock_validate_ip):
    """Test scan_tcp_port_with_banner with open port and banner."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]

    with patch('scanner.core.scanner._connect') as mock_connect:
        mock_socket_instance = Mock()
        mock_connect.return_value.__enter__.return_value = mock_socket_instance
        mock_socket_instance.recv.side_effect = [b"HTTP/1.1 200 OK\r\n", b""]  # Banner then timeout

        is_open, banner = scan_tcp_port_with_banner("127.0.0.1", 80, 0.5)

        assert is_open is True
        assert banner == "HTTP/1.1 200 OK\r\n"


@patch('scanner.core.scanner.validate_ip_address')
@patch('scanner.core.scanner.parse_ports')
def test_scan_tcp_port_still_works(mock_parse_ports, mock_validate_ip):
    """Test that original scan_tcp_port function still works unchanged."""
    mock_validate_ip.return_value = "127.0.0.1"
    mock_parse_ports.return_value = [80]

    with patch('scanner.core.scanner._connect') as mock_connect:
        mock_connect.return_value.__enter__.return_value = Mock()

        result = scan_tcp_port("127.0.0.1", 80, 0.5)

        assert result is True


def test_grab_banner_dns_error():
    """Test _grab_banner handles DNS errors gracefully."""
    mock_sock = Mock()
    mock_sock.recv.side_effect = socket.gaierror("DNS resolution failed")

    result = _grab_banner(mock_sock, 80, 1.0)
    assert result is None


def test_grab_banner_socket_error():
    """Test _grab_banner handles socket errors gracefully."""
    mock_sock = Mock()
    mock_sock.recv.side_effect = socket.error("Connection reset")

    result = _grab_banner(mock_sock, 80, 1.0)
    assert result is None
