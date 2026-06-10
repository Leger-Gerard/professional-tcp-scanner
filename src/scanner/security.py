"""Network enrichment helpers used by the scanner."""

from __future__ import annotations

import socket
import ssl
from typing import Any, cast

from scanner.models import TlsCertificateInfo

TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}


def reverse_dns_lookup(host: str) -> str | None:
    """Resolve a PTR record for IP targets when available."""
    try:
        return socket.gethostbyaddr(host)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


def inspect_tls_certificate(host: str, port: int, timeout: float) -> TlsCertificateInfo | None:
    """Inspect a peer TLS certificate.

    This function collects metadata for assessment reporting; it does not use
    certificate validation as an authentication decision.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = cast(dict[str, Any], tls_sock.getpeercert())
    except (OSError, ssl.SSLError, TimeoutError):
        return None

    return _certificate_from_peer_dict(cert)


def _certificate_from_peer_dict(cert: dict[str, Any]) -> TlsCertificateInfo | None:
    if not cert:
        return None

    subject = _format_name(cert.get("subject", ()))
    issuer = _format_name(cert.get("issuer", ()))
    san = [
        value
        for key, value in cert.get("subjectAltName", ())
        if key.lower() in {"dns", "ip address"}
    ]

    return TlsCertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=str(cert.get("notBefore", "")),
        not_after=str(cert.get("notAfter", "")),
        serial_number=str(cert.get("serialNumber", "")),
        san=san,
    )


def _format_name(name_parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    values: list[str] = []
    for group in name_parts:
        for key, value in group:
            values.append(f"{key}={value}")
    return ", ".join(values)
