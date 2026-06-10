# Security Model

## Authorized Use

The scanner is designed for authorized assessments, demos, labs, and internal diagnostics. It deliberately avoids stealth claims beyond bounded timing and concurrency profiles.

## Safety Controls

- `safe` profile: low concurrency and limited port count.
- `normal` profile: balanced default without implicit active banner/TLS probing.
- `aggressive` profile: high-throughput mode for controlled lab use.
- `--stealth`: lowers concurrency and increases timeout without pretending to be evasion.

## Output Security

- JSON, CSV, Markdown, and HTML reports are generated from typed models.
- HTML report fields are escaped.
- Logs are kept out of machine-readable stdout by default.

## Network Behavior

- TCP connect scans only.
- Optional banner grabbing uses bounded socket timeouts.
- TLS certificate inspection uses Python `ssl.create_default_context`.
- Reverse DNS is best effort and never required for scan success.
