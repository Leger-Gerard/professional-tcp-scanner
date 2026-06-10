"""Professional CLI interface for the TCP port scanner."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional, cast

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from scanner.core.scanner import (
    parse_ports,
    scan_tcp_port,
    scan_tcp_port_with_banner,
    validate_ip_address,
    validate_max_threads,
    validate_timeout,
)
from scanner.engines import BannerResult, ScanResults, ThreadedScanEngine
from scanner.models import PortFinding, ScanReport, score_port_risk
from scanner.policies import ScanProfileName, get_policy
from scanner.reporting import serialize_report
from scanner.security import inspect_tls_certificate, reverse_dns_lookup
from scanner.services.service_detector import get_service_name

console = Console()

app = typer.Typer(
    name="port-scanner",
    help="Professional TCP port scanner for security assessments",
    add_completion=False,
    rich_markup_mode="rich",
)


ReportFormat = Literal["table", "json", "csv", "markdown", "html"]

logger = logging.getLogger(__name__)


class _NoopProgress:
    """Progress-compatible object for machine-readable output paths."""

    def update(self, task_id: TaskID, advance: int = 1) -> None:
        return None


def validate_timeout_option(value: float) -> float:
    """Validate timeout CLI option."""
    try:
        return validate_timeout(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def validate_threads_option(value: int) -> int:
    """Validate threads CLI option."""
    try:
        return validate_max_threads(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def validate_report_format(value: str) -> ReportFormat:
    """Validate report format CLI option."""
    allowed = {"table", "json", "csv", "markdown", "html"}
    if value not in allowed:
        raise typer.BadParameter(f"Format must be one of: {', '.join(sorted(allowed))}")
    return cast(ReportFormat, value)


def setup_logging(
    verbose: bool = False,
    log_file: Optional[Path] = None,
    quiet_console: bool = False,
) -> None:
    """Configure application logging."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = []

    if not quiet_console:
        handlers.append(RichHandler(console=Console(stderr=True), rich_tracebacks=True))

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
        force=True,
    )


@app.command()
def scan(
    host: str = typer.Option(..., "--host", "-h", help="Target host or IP address"),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Ports to scan"),
    timeout: float = typer.Option(
        0.5,
        "--timeout",
        "-t",
        callback=validate_timeout_option,
        help="Connection timeout in seconds",
    ),
    threads: int = typer.Option(
        100,
        "--threads",
        callback=validate_threads_option,
        help="Maximum concurrent threads",
    ),
    json_output: bool = typer.Option(
        False,
        "--json-output",
        "-j",
        help="Output JSON (legacy alias for --format json)",
    ),
    output_format: ReportFormat = typer.Option(
        "table",
        "--format",
        "-f",
        callback=validate_report_format,
        help="Output format: table, json, csv, markdown, html",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for json, csv, markdown, or html reports",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logs"),
    stealth: bool = typer.Option(False, "--stealth", help="Enable stealth mode"),
    profile: ScanProfileName = typer.Option(
        "normal",
        "--profile",
        help="Scan policy profile: safe, normal, aggressive",
    ),
    banner: bool = typer.Option(True, "--banner/--no-banner", help="Show CLI banner"),
    banner_grab: bool = typer.Option(
        False,
        "--banner-grab",
        "-b",
        help="Attempt to grab service banners from open ports",
    ),
    tls_inspect: bool = typer.Option(
        False,
        "--tls-inspect",
        help="Inspect TLS certificates on common TLS ports",
    ),
    reverse_dns: bool = typer.Option(
        False,
        "--reverse-dns",
        help="Resolve reverse DNS for IP targets",
    ),
) -> None:
    """Scan TCP ports on a target host."""
    if json_output:
        output_format = "json"

    machine_output = output_format != "table"
    setup_logging(verbose, quiet_console=machine_output and not verbose)
    scan_logger = logging.getLogger(__name__)

    try:
        if banner and not machine_output:
            show_banner()

        policy = get_policy(profile)
        if stealth:
            timeout = max(timeout, 1.0)
            threads = min(threads, 50)
            if not machine_output:
                console.print("[yellow]Stealth mode enabled[/yellow]")

        validated_host = validate_ip_address(host)
        port_list = parse_ports(ports)
        port_list, timeout, threads = policy.apply(port_list, timeout, threads)
        banner_grab = banner_grab or policy.banner_grab
        tls_inspect = tls_inspect or policy.tls_inspection

        if not machine_output:
            console.print(f"\nTarget: [cyan]{validated_host}[/cyan]")
            console.print(f"Ports: [cyan]{len(port_list)} ports[/cyan]")
            console.print(f"Timeout: [cyan]{timeout}s[/cyan]")
            console.print(f"Threads: [cyan]{threads}[/cyan]")
            console.print(f"Profile: [cyan]{policy.name}[/cyan]\n")

        started_at = datetime.now()
        if machine_output:
            scan_results = _scan_without_progress(
                validated_host,
                port_list,
                timeout,
                threads,
                grab_banner=banner_grab,
            )
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning ports...", total=len(port_list))
                scan_results = _scan_with_progress(
                    validated_host,
                    port_list,
                    timeout,
                    threads,
                    progress,
                    task,
                    grab_banner=banner_grab,
                )

        duration = (datetime.now() - started_at).total_seconds()
        report = _build_scan_report(
            validated_host,
            scan_results,
            started_at,
            duration,
            len(port_list),
            profile=policy.name,
            banner_grab=banner_grab,
            tls_inspection=tls_inspect,
            reverse_dns=reverse_dns,
            timeout=timeout,
        )

        _display_results(report, output_format, output)

        scan_logger.info(
            "Scan completed: %s open ports found in %.2fs",
            report.open_ports_count,
            duration,
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1) from None
    except typer.Exit:
        raise
    except Exception as exc:
        scan_logger.error("Scan failed: %s", exc)
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


def _scan_without_progress(
    host: str,
    ports: list[int],
    timeout: float,
    max_threads: int,
    grab_banner: bool = False,
) -> ScanResults:
    """Scan ports without terminal progress output."""
    return _scan_with_progress(
        host,
        ports,
        timeout,
        max_threads,
        cast(Progress, _NoopProgress()),
        cast(TaskID, 0),
        grab_banner=grab_banner,
    )


def _scan_with_progress(
    host: str,
    ports: list[int],
    timeout: float,
    max_threads: int,
    progress: Progress,
    task_id: TaskID,
    grab_banner: bool = False,
) -> ScanResults:
    """Scan ports with progress updates."""
    engine = ThreadedScanEngine(
        scan_port=scan_tcp_port,
        scan_port_with_banner=scan_tcp_port_with_banner,
    )
    return engine.scan(
        host,
        ports,
        timeout,
        max_threads,
        grab_banner=grab_banner,
        progress_callback=lambda _port: progress.update(task_id, advance=1),
    )


def _build_scan_report(
    host: str,
    scan_results: ScanResults,
    started_at: datetime,
    duration: float,
    total_ports: int,
    profile: str,
    banner_grab: bool,
    tls_inspection: bool,
    reverse_dns: bool,
    timeout: float,
) -> ScanReport:
    """Convert raw scan results into a typed report."""
    findings: list[PortFinding] = []
    if banner_grab:
        banner_results = cast(list[BannerResult], scan_results)
        for item in banner_results:
            port = item["port"]
            tls_certificate = (
                inspect_tls_certificate(host, port, timeout) if tls_inspection else None
            )
            tls_detected = tls_certificate is not None
            risk, risk_score, notes = score_port_risk(
                port,
                item["service"],
                item["banner"],
                tls=tls_detected,
            )
            findings.append(
                PortFinding(
                    port=port,
                    status=item["status"],
                    service=item["service"],
                    banner=item["banner"],
                    tls=tls_detected,
                    tls_certificate=tls_certificate,
                    risk=risk,
                    risk_score=risk_score,
                    notes=notes,
                )
            )
    else:
        open_ports = cast(list[int], scan_results)
        for port in open_ports:
            service = get_service_name(port) or "unknown"
            tls_certificate = (
                inspect_tls_certificate(host, port, timeout) if tls_inspection else None
            )
            tls_detected = tls_certificate is not None
            risk, risk_score, notes = score_port_risk(port, service, tls=tls_detected)
            findings.append(
                PortFinding(
                    port=port,
                    status="open",
                    service=service,
                    tls=tls_detected,
                    tls_certificate=tls_certificate,
                    risk=risk,
                    risk_score=risk_score,
                    notes=notes,
                )
            )

    return ScanReport(
        target=host,
        started_at=started_at,
        duration_seconds=duration,
        total_ports_scanned=total_ports,
        findings=sorted(findings, key=lambda finding: finding.port),
        profile=profile,
        reverse_dns=reverse_dns_lookup(host) if reverse_dns else None,
        banner_grab_enabled=banner_grab,
        tls_inspection_enabled=tls_inspection,
    )


def _display_results(
    report: ScanReport,
    output_format: ReportFormat,
    output: Optional[Path] = None,
) -> None:
    """Display or write scan results."""
    if output_format != "table":
        report_text = serialize_report(report, output_format)
        if output is not None:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(report_text, encoding="utf-8")
                logger.info("%s report written to %s", output_format, output)
            except OSError as exc:
                message = f"Failed to write JSON report: {exc}" if output_format == "json" else f"Failed to write report: {exc}"
                logger.error(message)
                console.print(f"[bold red]Error:[/bold red] {message}")
                raise typer.Exit(1) from exc
        else:
            console.print(report_text)
        return

    console.print()
    if not report.findings:
        console.print(f"[yellow]No open ports found on {report.target}[/yellow]")
    else:
        table = Table(title=f"Open Ports on {report.target}")
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Risk", style="red")
        table.add_column("Score", justify="right")
        table.add_column("Banner", style="dim", max_width=60)

        for finding in report.findings:
            banner_text = finding.banner or "[no banner]"
            if len(banner_text) > 60:
                banner_text = banner_text[:57] + "..."
            table.add_row(
                str(finding.port),
                finding.status.upper(),
                finding.service,
                finding.risk.upper(),
                str(finding.risk_score),
                banner_text,
            )
        console.print(table)

    summary = (
        f"Target: {report.target}\n"
        f"Duration: {report.duration_seconds:.2f} seconds\n"
        f"Ports Scanned: {report.total_ports_scanned}\n"
        f"Open Ports Found: {report.open_ports_count}\n"
        f"Highest Risk: {report.highest_risk.upper()}\n"
        f"Reverse DNS: {report.reverse_dns or 'n/a'}"
    )
    console.print(Panel(summary, title="Scan Summary", border_style="blue"))


def _build_json_report(
    host: str,
    scan_results: ScanResults,
    duration: float,
    total_ports: int,
    banner_grab: bool,
) -> dict[str, object]:
    """Backward-compatible JSON report helper used by existing tests."""
    report = _build_scan_report(
        host=host,
        scan_results=scan_results,
        started_at=datetime.now(),
        duration=duration,
        total_ports=total_ports,
        profile="normal",
        banner_grab=banner_grab,
        tls_inspection=False,
        reverse_dns=False,
        timeout=0.5,
    )
    data = report.to_dict()
    if not banner_grab:
        data["open_ports"] = [
            {"port": finding.port, "service": finding.service}
            for finding in report.findings
        ]
    return data


@app.command()
def version() -> None:
    """Show version information."""
    console.print("TCP Port Scanner v1.0.0")


def show_banner() -> None:
    """Display application banner."""
    banner_text = """
==============================
     TCP Port Scanner v1.0.0
==============================
Professional TCP Port Scanner for Security Assessments
"""
    console.print(Panel(banner_text, border_style="blue"))


def main() -> None:
    """Application entry point."""
    app()


if __name__ == "__main__":
    main()
