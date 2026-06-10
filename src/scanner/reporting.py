"""Report serialization helpers for CLI and automation outputs."""

from __future__ import annotations

import csv
import html
import io
import json

from scanner.models import ScanReport


def serialize_report(report: ScanReport, output_format: str) -> str:
    """Serialize a report to json, csv, markdown, or html."""
    match output_format:
        case "json":
            return json.dumps(report.to_dict(), indent=2)
        case "csv":
            return _to_csv(report)
        case "markdown":
            return _to_markdown(report)
        case "html":
            return _to_html(report)
        case _:
            raise ValueError(f"Unsupported report format: {output_format}")


def _to_csv(report: ScanReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["port", "status", "service", "risk", "risk_score", "tls", "banner"],
    )
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(
            {
                "port": finding.port,
                "status": finding.status,
                "service": finding.service,
                "risk": finding.risk,
                "risk_score": finding.risk_score,
                "tls": finding.tls,
                "banner": finding.banner,
            }
        )
    return buffer.getvalue()


def _to_markdown(report: ScanReport) -> str:
    lines = [
        f"# TCP Scan Report: {report.target}",
        "",
        f"- Timestamp: `{report.started_at.isoformat()}`",
        f"- Duration: `{report.duration_seconds:.2f}s`",
        f"- Ports scanned: `{report.total_ports_scanned}`",
        f"- Open ports: `{report.open_ports_count}`",
        f"- Highest risk: `{report.highest_risk}`",
        f"- Reverse DNS: `{report.reverse_dns or 'n/a'}`",
        "",
        "| Port | Service | Risk | Score | TLS | Banner |",
        "| ---: | --- | --- | ---: | --- | --- |",
    ]
    for finding in report.findings:
        banner = finding.banner.replace("\n", " ").replace("|", "\\|")[:120]
        lines.append(
            f"| {finding.port} | {finding.service} | {finding.risk} | "
            f"{finding.risk_score} | {finding.tls} | {banner} |"
        )
    return "\n".join(lines) + "\n"


def _to_html(report: ScanReport) -> str:
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{finding.port}</td>"
            f"<td>{html.escape(finding.service)}</td>"
            f"<td>{finding.risk}</td>"
            f"<td>{finding.risk_score}</td>"
            f"<td>{finding.tls}</td>"
            f"<td>{html.escape(finding.banner[:200])}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>TCP Scan Report - {html.escape(report.target)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #17202a; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d5d8dc; padding: 0.5rem; text-align: left; }}
    th {{ background: #f4f6f7; }}
  </style>
</head>
<body>
  <h1>TCP Scan Report: {html.escape(report.target)}</h1>
  <p><strong>Duration:</strong> {report.duration_seconds:.2f}s</p>
  <p><strong>Ports scanned:</strong> {report.total_ports_scanned}</p>
  <p><strong>Open ports:</strong> {report.open_ports_count}</p>
  <p><strong>Highest risk:</strong> {report.highest_risk}</p>
  <p><strong>Reverse DNS:</strong> {html.escape(report.reverse_dns or "n/a")}</p>
  <table>
    <thead>
      <tr><th>Port</th><th>Service</th><th>Risk</th><th>Score</th><th>TLS</th><th>Banner</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
