"""Unit tests for scan engine implementations."""

from scanner.engines import ScanEngine, ThreadedScanEngine


def test_threaded_scan_engine_returns_sorted_open_ports() -> None:
    progress_updates: list[int] = []

    def scan_port(host: str, port: int, timeout: float) -> bool:
        return port in {443, 80}

    engine: ScanEngine = ThreadedScanEngine(scan_port=scan_port)

    results = engine.scan(
        "127.0.0.1",
        [443, 22, 80],
        0.5,
        3,
        progress_callback=progress_updates.append,
    )

    assert results == [80, 443]
    assert sorted(progress_updates) == [22, 80, 443]


def test_threaded_scan_engine_handles_port_scan_exceptions() -> None:
    def scan_port(host: str, port: int, timeout: float) -> bool:
        if port == 22:
            raise OSError("boom")
        return port == 80

    engine = ThreadedScanEngine(scan_port=scan_port)

    assert engine.scan("127.0.0.1", [22, 80], 0.5, 2) == [80]


def test_threaded_scan_engine_returns_banner_results() -> None:
    progress_updates: list[int] = []

    def scan_with_banner(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
        if port == 80:
            return True, "HTTP/1.1 200 OK"
        return False, None

    engine = ThreadedScanEngine(scan_port_with_banner=scan_with_banner)

    results = engine.scan(
        "127.0.0.1",
        [81, 80],
        0.5,
        2,
        grab_banner=True,
        progress_callback=progress_updates.append,
    )

    assert results == [
        {
            "port": 80,
            "status": "open",
            "service": "HTTP",
            "banner": "HTTP/1.1 200 OK",
        }
    ]
    assert sorted(progress_updates) == [80, 81]


def test_threaded_scan_engine_handles_banner_scan_exceptions() -> None:
    def scan_with_banner(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
        if port == 22:
            raise OSError("boom")
        return True, None

    engine = ThreadedScanEngine(scan_port_with_banner=scan_with_banner)

    results = engine.scan("127.0.0.1", [22, 12345], 0.5, 2, grab_banner=True)

    assert results == [
        {
            "port": 12345,
            "status": "open",
            "service": "unknown",
            "banner": "",
        }
    ]


def test_threaded_scan_engine_empty_ports() -> None:
    engine = ThreadedScanEngine()

    assert engine.scan("127.0.0.1", [], 0.5, 10) == []
