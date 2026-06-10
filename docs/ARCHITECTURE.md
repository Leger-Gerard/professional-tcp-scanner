# Architecture

## Overview

The project is a Python TCP connect scanner with a Typer CLI, typed scan reports, policy-based scan limits, service enrichment, optional banner grabbing, optional TLS certificate inspection, and multi-format reporting.

## Module Layout

```text
src/scanner/
  cli/main.py              CLI orchestration and terminal UX
  core/scanner.py          TCP scanning, port parsing, validation, banner grabbing
  engines.py               Scan engine protocol and threaded scan engine
  models.py                Typed scan findings, reports, and risk scoring
  policies.py              Safe, normal, and aggressive scan profiles
  reporting.py             JSON, CSV, Markdown, and HTML serializers
  security.py              Reverse DNS and TLS certificate inspection helpers
  services/service_detector.py
                           Static well-known port mapping
```

## Data Flow

```text
CLI options
  -> input validation
  -> scan policy profile
  -> TCP scan engine
  -> optional banner/TLS/reverse DNS enrichment
  -> risk scoring
  -> ScanReport model
  -> terminal table or machine-readable report
```

## Extension Points

- Add new report formats in `scanner.reporting.serialize_report`.
- Add scan engines by implementing `scanner.engines.ScanEngine`.
- Add service probes in `scanner.core.scanner._grab_banner`.
- Add richer risk rules in `scanner.models.score_port_risk`.
- Add policy profiles in `scanner.policies.POLICIES`.

## Design Principles

- KISS: standard-library networking, no framework-heavy scanner runtime.
- DRY: validation and report serialization are centralized.
- SOLID: scanning, policy, reporting, and enrichment responsibilities are separated.
- Safety first: profiles bound concurrency, timeout, and port counts.
