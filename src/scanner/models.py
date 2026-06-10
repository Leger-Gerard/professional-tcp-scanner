"""Typed scan result models and risk scoring helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal

RiskLevel = Literal["info", "low", "medium", "high"]

HIGH_RISK_PORTS = {21, 23, 445, 1433, 3306, 5432, 5900, 6379, 27017, 9200}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 139, 143, 389, 3389, 8080, 8443}


@dataclass(frozen=True)
class TlsCertificateInfo:
    """Minimal TLS certificate metadata useful for scan reports."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial_number: str
    san: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PortFinding:
    """One open TCP port finding."""

    port: int
    status: str
    service: str
    banner: str = ""
    tls: bool = False
    tls_certificate: TlsCertificateInfo | None = None
    risk: RiskLevel = "info"
    risk_score: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to plain JSON-compatible data."""
        data = asdict(self)
        if self.tls_certificate is None:
            data["tls_certificate"] = None
        return data


@dataclass(frozen=True)
class ScanReport:
    """Complete scan report payload."""

    target: str
    started_at: datetime
    duration_seconds: float
    total_ports_scanned: int
    findings: list[PortFinding]
    profile: str
    reverse_dns: str | None = None
    banner_grab_enabled: bool = False
    tls_inspection_enabled: bool = False

    @property
    def open_ports_count(self) -> int:
        return len(self.findings)

    @property
    def highest_risk(self) -> RiskLevel:
        order: dict[RiskLevel, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
        highest: RiskLevel = "info"
        for finding in self.findings:
            if order[finding.risk] > order[highest]:
                highest = finding.risk
        return highest

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to stable JSON-compatible data."""
        return {
            "target": self.target,
            "timestamp": self.started_at.isoformat(),
            "scan_duration_seconds": round(self.duration_seconds, 2),
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports": [finding.to_dict() for finding in self.findings],
            "open_ports_count": self.open_ports_count,
            "highest_risk": self.highest_risk,
            "profile": self.profile,
            "reverse_dns": self.reverse_dns,
            "banner_grab_enabled": self.banner_grab_enabled,
            "tls_inspection_enabled": self.tls_inspection_enabled,
        }


def score_port_risk(port: int, service: str, banner: str = "", tls: bool = False) -> tuple[RiskLevel, int, list[str]]:
    """Assign a simple, explainable risk score to an open port."""
    notes: list[str] = []
    normalized_service = service.lower()
    normalized_banner = banner.lower()

    if port in HIGH_RISK_PORTS:
        notes.append("commonly targeted administrative or data service")
        base = 70
    elif port in MEDIUM_RISK_PORTS:
        notes.append("commonly exposed infrastructure service")
        base = 45
    else:
        base = 20

    if "telnet" in normalized_service or port == 23:
        base += 20
        notes.append("cleartext remote administration")
    if any(token in normalized_banner for token in ("anonymous", "default", "unauthorized")):
        base += 10
        notes.append("banner contains potentially sensitive security signal")
    if port in {80, 8080} and not tls:
        base += 5
        notes.append("plaintext HTTP exposure")

    score = min(base, 100)
    if score >= 70:
        return "high", score, notes
    if score >= 40:
        return "medium", score, notes
    if score >= 20:
        return "low", score, notes
    return "info", score, notes
