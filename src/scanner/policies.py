"""Scan policy profiles for predictable and safe scanner behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ScanProfileName = Literal["safe", "normal", "aggressive"]


@dataclass(frozen=True)
class ScanPolicy:
    """Operational limits applied to a scan."""

    name: ScanProfileName
    max_threads: int
    min_timeout: float
    max_ports: int
    banner_grab: bool
    tls_inspection: bool
    description: str

    def apply(self, ports: list[int], timeout: float, threads: int) -> tuple[list[int], float, int]:
        """Clamp requested scan parameters to this policy."""
        if len(ports) > self.max_ports:
            raise ValueError(
                f"Profile '{self.name}' allows at most {self.max_ports} ports per scan"
            )
        return ports, max(timeout, self.min_timeout), min(threads, self.max_threads)


POLICIES: dict[ScanProfileName, ScanPolicy] = {
    "safe": ScanPolicy(
        name="safe",
        max_threads=25,
        min_timeout=1.0,
        max_ports=1024,
        banner_grab=False,
        tls_inspection=False,
        description="Low-noise scan profile for demonstrations and cautious environments.",
    ),
    "normal": ScanPolicy(
        name="normal",
        max_threads=200,
        min_timeout=0.5,
        max_ports=10000,
        banner_grab=False,
        tls_inspection=False,
        description="Balanced profile for authorized internal assessments.",
    ),
    "aggressive": ScanPolicy(
        name="aggressive",
        max_threads=1000,
        min_timeout=0.1,
        max_ports=65535,
        banner_grab=True,
        tls_inspection=True,
        description="High-throughput profile for controlled lab environments.",
    ),
}


def get_policy(profile: ScanProfileName) -> ScanPolicy:
    """Return a scan policy by name."""
    return POLICIES[profile]
