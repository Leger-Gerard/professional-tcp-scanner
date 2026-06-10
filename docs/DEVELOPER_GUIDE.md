# Developer Guide

## Setup

```powershell
$env:UV_CACHE_DIR='D:\TP_CYBER\.uv-cache'
$env:UV_PYTHON_INSTALL_DIR='D:\TP_CYBER\.uv-python'
$env:UV_PROJECT_ENVIRONMENT='D:\TP_CYBER\.uv-venv'
uv run --extra dev python -m pytest
```

## Checks

```bash
uv run --extra dev python -m pytest --cov=src --cov-report=term-missing
uv run --extra dev ruff check src tests
uv run --extra dev mypy src
```

## Test Suites

```bash
uv run --extra dev python -m pytest tests/unit
uv run --extra dev python -m pytest tests/integration
uv run --extra dev python -m pytest -m integration tests/integration
```

Integration tests bind only to `127.0.0.1` with ephemeral ports. They do not require external network access and are intended to validate the real TCP scan path, TLS inspection when local certificate tooling is available, and CLI JSON/HTML reporting against live local sockets.

## Adding Features

- Add scan result fields to `scanner.models`.
- Add scan execution strategies in `scanner.engines`.
- Keep CLI-specific logic in `scanner.cli.main`.
- Add serializers in `scanner.reporting`.
- Add policy constraints in `scanner.policies`.
- Mock `scanner.core.scanner._connect` for low-level socket behavior.
- Inject callables into `ThreadedScanEngine` for engine orchestration tests.

## Quality Bar

- New behavior needs unit tests.
- New output formats need serializer tests.
- New network behavior needs mocked tests and bounded timeouts.
