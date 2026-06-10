# CLAUDE.md

This file provides guidance for coding agents working in this repository.

## Development Commands

- Run tests: `uv run --extra dev python -m pytest`
- Run tests with coverage: `uv run --extra dev python -m pytest --cov=src --cov-report=term-missing`
- Lint: `uv run --extra dev ruff check src tests`
- Type check: `uv run --extra dev mypy src`
- Run the CLI: `uv run port-scanner scan --host 127.0.0.1 --ports 80,443`

If the local `.venv` is broken, use a project-local uv environment:

```powershell
$env:UV_CACHE_DIR='D:\TP_CYBER\.uv-cache'
$env:UV_PYTHON_INSTALL_DIR='D:\TP_CYBER\.uv-python'
$env:UV_PROJECT_ENVIRONMENT='D:\TP_CYBER\.uv-venv'
uv run --extra dev python -m pytest
```

## Project Structure

- `main.py`: simple application entry point.
- `src/scanner/cli/main.py`: Typer/Rich command-line interface.
- `src/scanner/core/scanner.py`: host, port, timeout, thread validation plus TCP scanning and banner grabbing.
- `src/scanner/services/service_detector.py`: static port-to-service mapping.
- `tests/unit/`: unit tests using mocks for network behavior.

## Architecture Notes

The scanner performs TCP connect scans with bounded timeouts and thread pools. Network connections go through `scanner.core.scanner._connect`, which uses `socket.create_connection` so IPv4 and IPv6 targets are both supported. Tests should mock `_connect` rather than low-level socket constructors.

The CLI supports human-readable output and JSON reports. JSON mode suppresses normal console logging unless verbose mode is enabled so stdout remains machine-readable.
