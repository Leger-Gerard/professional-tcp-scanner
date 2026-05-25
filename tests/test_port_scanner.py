import pytest
from unittest.mock import patch, MagicMock
from src.scanner.port_scanner import scan_port, main

def test_scan_port_open():
    """Test scan_port returns True when port is open."""
    with patch('socket.socket') as mock_socket:
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_instance

        result = scan_port('localhost', 80)
        assert result is True

def test_scan_port_closed():
    """Test scan_port returns False when port is closed."""
    with patch('socket.socket') as mock_socket:
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 1  # Connection refused
        mock_socket.return_value.__enter__.return_value = mock_instance

        result = scan_port('localhost', 81)
        assert result is False

def test_scan_port_timeout():
    """Test scan_port handles timeout (returns False)."""
    with patch('socket.socket') as mock_socket:
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 110  # Connection timed out
        mock_socket.return_value.__enter__.return_value = mock_instance

        result = scan_port('localhost', 82)
        assert result is False

@patch('builtins.input', side_effect=['localhost', '80', '81'])
@patch('src.scanner.port_scanner.scan_port')
def test_main_scan_range(mock_scan_port, mock_input):
    """Test main function scans range and reports results."""
    # Mock scan_port to return True for port 80, False for 81
    mock_scan_port.side_effect = [True, False]

    # Capture stdout
    from io import StringIO
    import sys

    # Redirect stdout
    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        main()
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout

    # Check that output contains expected strings
    assert '[OUVERT] Port 80' in output
    assert 'Ports ouverts : 80' in output
    assert 'Temps d\'exécution' in output

@patch('builtins.input', side_effect=['localhost', '90', '91'])
@patch('src.scanner.port_scanner.scan_port')
def test_main_no_open_ports(mock_scan_port, mock_input):
    """Test main function when no ports are open."""
    mock_scan_port.return_value = False

    from io import StringIO
    import sys

    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        main()
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout

    assert 'Aucun port ouvert détecté.' in output