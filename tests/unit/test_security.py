"""Unit tests for security enrichment helpers."""

import socket
from unittest.mock import Mock, patch

from scanner.security import (
    _certificate_from_peer_dict,
    _format_name,
    inspect_tls_certificate,
    reverse_dns_lookup,
)


def test_reverse_dns_lookup_success():
    with patch("scanner.security.socket.gethostbyaddr") as mock_lookup:
        mock_lookup.return_value = ("localhost", [], ["127.0.0.1"])

        assert reverse_dns_lookup("127.0.0.1") == "localhost"


def test_reverse_dns_lookup_failure():
    with patch("scanner.security.socket.gethostbyaddr") as mock_lookup:
        mock_lookup.side_effect = socket.herror("not found")

        assert reverse_dns_lookup("127.0.0.1") is None


def test_format_name():
    name = (((("commonName", "example.com"),),))

    assert _format_name(name) == "commonName=example.com"


def test_certificate_from_peer_dict():
    cert = _certificate_from_peer_dict(
        {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "serialNumber": "01",
            "subjectAltName": (("DNS", "example.com"), ("IP Address", "127.0.0.1")),
        }
    )

    assert cert is not None
    assert cert.subject == "commonName=example.com"
    assert cert.issuer == "commonName=Example CA"
    assert cert.san == ["example.com", "127.0.0.1"]


def test_certificate_from_empty_peer_dict():
    assert _certificate_from_peer_dict({}) is None


def test_inspect_tls_certificate_handles_errors():
    with patch("scanner.security.socket.create_connection") as mock_connection:
        mock_connection.side_effect = OSError("refused")

        assert inspect_tls_certificate("example.com", 443, 1.0) is None


def test_inspect_tls_certificate_success():
    raw_sock = Mock()
    tls_sock = Mock()
    tls_sock.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
        "serialNumber": "01",
    }

    with patch("scanner.security.socket.create_connection") as mock_connection:
        with patch("scanner.security.ssl.create_default_context") as mock_context:
            mock_connection.return_value.__enter__.return_value = raw_sock
            mock_context.return_value.wrap_socket.return_value.__enter__.return_value = tls_sock

            cert = inspect_tls_certificate("example.com", 443, 1.0)

    assert cert is not None
    assert cert.subject == "commonName=example.com"
