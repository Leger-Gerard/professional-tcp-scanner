"""Integration-test fixtures for local TCP and TLS services."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from shutil import which

import pytest


@dataclass(frozen=True)
class LocalServerEndpoint:
    host: str
    port: int


class LocalTcpServer:
    """Small local TCP server for deterministic scanner integration tests."""

    def __init__(self, banner: bytes = b"", max_connections: int = 16) -> None:
        self.banner = banner
        self.max_connections = max_connections
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._server: socket.socket | None = None
        self.endpoint = LocalServerEndpoint("127.0.0.1", 0)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=2):
            raise RuntimeError("local TCP server did not start")

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _serve_connection(self, conn: socket.socket) -> None:
        conn.settimeout(0.2)
        if self.banner:
            conn.sendall(self.banner)
        try:
            conn.recv(1024)
        except OSError:
            pass

    def _serve(self) -> None:
        served = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.endpoint.host, 0))
            server.listen()
            server.settimeout(0.1)
            self._server = server
            self.endpoint = LocalServerEndpoint(self.endpoint.host, int(server.getsockname()[1]))
            self._ready.set()

            while not self._stop.is_set() and served < self.max_connections:
                try:
                    conn, _addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                served += 1
                with conn:
                    self._serve_connection(conn)


class LocalTlsServer(LocalTcpServer):
    """Local TLS server backed by a runtime-generated self-signed certificate."""

    def __init__(self, cert_file: Path, key_file: Path, max_connections: int = 16) -> None:
        super().__init__(banner=b"", max_connections=max_connections)
        self.cert_file = cert_file
        self.key_file = key_file
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            with self._context.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.settimeout(0.2)
                try:
                    tls_conn.recv(1024)
                except OSError:
                    pass
        except ssl.SSLError:
            pass


@pytest.fixture
def local_tcp_server() -> Iterator[LocalTcpServer]:
    server = LocalTcpServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def local_banner_server() -> Iterator[LocalTcpServer]:
    server = LocalTcpServer(banner=b"SSH-2.0-TestServer\r\n")
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def tls_certificate_files(tmp_path: Path) -> tuple[Path, Path]:
    openssl = which("openssl")
    if openssl is None:
        pytest.skip("openssl is required to generate an ephemeral TLS certificate")

    key_file = tmp_path / "localhost.key"
    cert_file = tmp_path / "localhost.crt"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return cert_file, key_file


@pytest.fixture
def local_tls_server(tls_certificate_files: tuple[Path, Path]) -> Iterator[LocalTlsServer]:
    cert_file, key_file = tls_certificate_files
    server = LocalTlsServer(cert_file=cert_file, key_file=key_file)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
