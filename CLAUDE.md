# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Run tests**: `python -m pytest`
- **Run tests with coverage**: `python -m pytest --cov=src --cov-report=term-missing`
- **Lint code**: `ruff check src` (ruff is in dev dependencies)
- **Format code**: `ruff check --fix src`
- **Type checking**: `mypy src`
- **Run the port scanner**: `python main.py` (will prompt for input)

## Project Structure

- `main.py`: Entry point that calls the scanner's main function.
- `src/scanner/port_scanner.py`: Contains the port scanning logic:
  - `scan_port(host: str, port: int, timeout: float) -> bool`: Checks if a TCP port is open.
  - `main() -> None`: Interactive CLI that scans a range of ports and reports results.
- `tests/`: Unit tests for the scanner using pytest and mocking.
- `pyproject.toml`: Project configuration with dependencies (requests, rich, typer) and dev dependencies (mypy, pytest, ruff).

## Architecture Overview

The port scanner is a simple TCP scanner that:
1. Takes user input for target host and port range.
2. For each port in the range, attempts a TCP connection with a short timeout.
3. Reports which ports are open (connection successful) and which are closed/filtered.
4. Measures and displays the total scan time.

The scanner uses the standard library `socket` module and does not require external dependencies for core functionality.

## Testing Approach

Tests use mocking to simulate network interactions:
- `socket.socket` is mocked to control the return value of `connect_ex`.
- Tests cover open ports, closed ports, and timeout scenarios.
- The main function is tested by mocking `input` and `scan_port` to verify output.
