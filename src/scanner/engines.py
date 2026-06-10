"""Scan engine abstractions.

This module separates scan orchestration from the CLI so additional engines
can be introduced without changing user-facing commands or report schemas.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Protocol, TypeAlias, TypedDict

from scanner.core.scanner import scan_tcp_port, scan_tcp_port_with_banner
from scanner.services.service_detector import get_service_name

logger = logging.getLogger(__name__)


class BannerResult(TypedDict):
    """Open port result enriched with a banner."""

    port: int
    status: str
    service: str
    banner: str


ScanResults: TypeAlias = list[int] | list[BannerResult]
ProgressCallback: TypeAlias = Callable[[int], None]
ScanPortCallable: TypeAlias = Callable[[str, int, float], bool]
BannerScanCallable: TypeAlias = Callable[[str, int, float], tuple[bool, str | None]]


class ScanEngine(Protocol):
    """Protocol implemented by scan engines."""

    def scan(
        self,
        host: str,
        ports: list[int],
        timeout: float,
        max_threads: int,
        *,
        grab_banner: bool = False,
        progress_callback: ProgressCallback | None = None,
    ) -> ScanResults:
        """Scan TCP ports and return open-port results."""


class ThreadedScanEngine:
    """ThreadPoolExecutor-based TCP scan engine."""

    def __init__(
        self,
        scan_port: ScanPortCallable = scan_tcp_port,
        scan_port_with_banner: BannerScanCallable = scan_tcp_port_with_banner,
    ) -> None:
        self._scan_port = scan_port
        self._scan_port_with_banner = scan_port_with_banner

    def scan(
        self,
        host: str,
        ports: list[int],
        timeout: float,
        max_threads: int,
        *,
        grab_banner: bool = False,
        progress_callback: ProgressCallback | None = None,
    ) -> ScanResults:
        """Scan TCP ports using a bounded thread pool."""
        if not ports:
            return []

        if grab_banner:
            return self._scan_with_banners(
                host,
                ports,
                timeout,
                max_threads,
                progress_callback,
            )

        return self._scan_ports(host, ports, timeout, max_threads, progress_callback)

    def _scan_ports(
        self,
        host: str,
        ports: list[int],
        timeout: float,
        max_threads: int,
        progress_callback: ProgressCallback | None,
    ) -> list[int]:
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
            future_to_port = {
                executor.submit(self._scan_port, host, port, timeout): port
                for port in ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as exc:
                    logger.error("Error scanning port %s: %s", port, exc)
                finally:
                    if progress_callback is not None:
                        progress_callback(port)

        return sorted(open_ports)

    def _scan_with_banners(
        self,
        host: str,
        ports: list[int],
        timeout: float,
        max_threads: int,
        progress_callback: ProgressCallback | None,
    ) -> list[BannerResult]:
        banner_results: list[BannerResult] = []
        with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
            future_to_port = {
                executor.submit(self._scan_port_with_banner, host, port, timeout): port
                for port in ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, grabbed_banner = future.result()
                    if is_open:
                        banner_results.append(
                            {
                                "port": port,
                                "status": "open",
                                "service": get_service_name(port) or "unknown",
                                "banner": grabbed_banner or "",
                            }
                        )
                except Exception as exc:
                    logger.error("Error scanning port %s: %s", port, exc)
                finally:
                    if progress_callback is not None:
                        progress_callback(port)

        return sorted(banner_results, key=lambda item: item["port"])
