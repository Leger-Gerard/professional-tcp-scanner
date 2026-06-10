# TCP Port Scanner

A Python TCP connect scanner for authorized security assessments and network diagnostics.

## Features

- Typer CLI with Rich terminal output
- Concurrent TCP connect scanning with bounded thread pools
- IPv4, IPv6, and hostname targets through `socket.create_connection`
- Strict host, port, timeout, and thread validation
- Safe, normal, and aggressive scan policy profiles
- Optional banner grabbing for common plaintext services
- Optional reverse DNS and TLS certificate inspection
- Human-readable tables plus JSON, CSV, Markdown, and HTML reports
- Explainable risk scoring for open ports
- Static service-name enrichment from well-known port mappings
- Unit-tested core, CLI, banner grabbing, and service detection paths
- Container image that runs as a non-root user

## Installation

```bash
pip install -e .
pip install -e ".[dev]"
```

The package exposes a `port-scanner` console script.

## Usage

```bash
port-scanner scan --host 127.0.0.1
port-scanner scan --host example.com --ports 80,443,8080
port-scanner scan --host 192.168.1.1 --ports 1-1000
port-scanner scan --host ::1 --ports 22,80,443
```

Advanced options:

```bash
port-scanner scan --host target.com --ports 80,443 --timeout 2.0 --threads 50
port-scanner scan --host target.com --json-output --output results.json
port-scanner scan --host target.com --format markdown --output report.md
port-scanner scan --host target.com --format html --output report.html
port-scanner scan --host target.com --stealth --threads 30
port-scanner scan --host target.com --banner-grab
port-scanner scan --host target.com --tls-inspect --reverse-dns
port-scanner scan --host target.com --profile safe
port-scanner scan --host target.com --no-banner
```

## Development

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m pytest --cov=src --cov-report=term-missing
uv run --extra dev ruff check src tests
uv run --extra dev mypy src
```

## Docker

```bash
docker build -t port-scanner .
docker run --rm port-scanner scan --host 127.0.0.1 --ports 80,443
docker run --rm -v "$(pwd)/results:/app/results" port-scanner scan \
  --host example.com --json-output --output /app/results/scan.json
```

## Security Notes

- This is a TCP connect scanner, not a raw SYN scanner.
- Banner grabbing is intentionally conservative and may not identify TLS-only services.
- Thread count and timeout are bounded to reduce accidental local resource exhaustion.
- JSON stdout is kept clean unless verbose logging is explicitly requested.
- Use only against systems and networks where you have authorization.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Contributing](CONTRIBUTING.md)

## Limitations

- TCP only; UDP scanning is not implemented.
- Service detection is static unless banner grabbing is enabled.
- Stealth mode only lowers concurrency and increases timeout; it is not advanced evasion.

## Disclaimer

This tool is intended for authorized security testing and education. Unauthorized scanning may be illegal. The authors are not responsible for misuse or damage caused by this software.
