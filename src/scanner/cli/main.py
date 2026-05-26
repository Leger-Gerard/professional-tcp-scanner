"""
Professional CLI interface for TCP port scanner using Typer and Rich.
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.logging import RichHandler

from scanner.core.scanner import (
    scan_ports,
    validate_ip_address,
    parse_ports,
    scan_tcp_port
)

# Initialize console and app
console = Console()
app = typer.Typer(
    name="port-scanner",
    help="Professional TCP port scanner for security assessments",
    add_completion=False,
    rich_markup_mode="rich"
)

# Setup logging
def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    """Setup logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            RichHandler(console=console, rich_tracebacks=True),
            logging.FileHandler(log_file) if log_file else logging.NullHandler()
        ]
    )


@app.command()
def scan(
    host: str = typer.Option(
        ...,
        "--host",
        "-h",
        help="Target host to scan (IP address or hostname)",
        prompt=True
    ),
    ports: str = typer.Option(
        "1-1024",
        "--ports",
        "-p",
        help="Port range to scan (e.g., '80,443' or '1-1000' or '80,443,8000-9000')"
    ),
    timeout: float = typer.Option(
        0.5,
        "--timeout",
        "-t",
        help="Connection timeout in seconds",
        min=0.1,
        max=30.0
    ),
    threads: int = typer.Option(
        100,
        "--threads",
        "-T",
        help="Maximum number of concurrent threads",
        min=1,
        max=1000
    ),
    json_output: bool = typer.Option(
        False,
        "--json-output",
        "-j",
        help="Output results in JSON format"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        "-s",
        help="Use slower scan timing to reduce detection likelihood"
    ),
    banner: bool = typer.Option(
        True,
        "--banner/--no-banner",
        help="Show or hide banner"
    )
) -> None:
    """
    Scan TCP ports on a target host.

    Examples:

    # Scan common ports on localhost
    port-scanner scan --host 127.0.0.1

    # Scan specific ports with custom timeout
    port-scanner scan --host example.com --ports 80,443,8080 --timeout 1.0

    # Full port scan with JSON output
    port-scanner scan --host 192.168.1.1 --ports 1-65535 --json-output --output results.json

    # Stealth scan for security assessments
    port-scanner scan --host target.com --stealth --threads 50
    """
    # Adjust timing for stealth mode
    if stealth:
        timeout = max(timeout, 2.0)  # Minimum 2s timeout for stealth
        threads = min(threads, 50)   # Max 50 threads for stealth

    # Setup logging
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "scan.log"
    setup_logging(verbose, log_file)

    logger = logging.getLogger(__name__)

    try:
        # Validate inputs
        validated_host = validate_ip_address(host)
        port_list = parse_ports(ports)

        # Show banner
        if banner:
            show_banner()

        # Display scan info
        console.print(f"\n[bold blue]Target:[/bold blue] {validated_host}")
        console.print(f"[bold blue]Ports:[/bold blue] {len(port_list)} ports")
        console.print(f"[bold blue]Timeout:[/bold blue] {timeout}s")
        console.print(f"[bold blue]Threads:[/bold blue] {threads}")
        if stealth:
            console.print("[yellow]Stealth mode enabled[/yellow]")
        console.print()

        # Perform scan with progress bar
        start_time = datetime.now()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:

            task = progress.add_task(
                f"Scanning {validated_host}...",
                total=len(port_list)
            )

            # Custom scan function with progress updates
            open_ports = _scan_with_progress(
                validated_host,
                port_list,
                timeout,
                threads,
                progress,
                task
            )

        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()

        # Display results
        _display_results(
            validated_host,
            open_ports,
            scan_duration,
            json_output,
            len(port_list)
        )

        # Log results
        logger.info(f"Scan completed: {len(open_ports)} open ports found in {scan_duration:.2f}s")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


def _scan_with_progress(
    host: str,
    ports: List[int],
    timeout: float,
    max_threads: int,
    progress: Progress,
    task_id
) -> List[int]:
    """
    Scan ports with progress bar updates.

    Args:
        host: Target host
        ports: Ports to scan
        timeout: Connection timeout
        max_threads: Max concurrent threads
        progress: Rich progress instance
        task_id: Progress task ID

    Returns:
        List of open ports
    """
    if not ports:
        return []

    open_ports: List[int] = []

    # Use ThreadPoolExecutor for controlled concurrency
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        # Submit all scan tasks
        future_to_port = {
            executor.submit(scan_tcp_port, host, port, timeout): port
            for port in ports
        }

        # Process results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    logger = logging.getLogger(__name__)
                    logger.debug(f"Port {port} is OPEN on {host}")
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Error scanning port {port}: {e}")
            finally:
                progress.update(task_id, advance=1)

    return sorted(open_ports)


def _display_results(
    host: str,
    open_ports: List[int],
    duration: float,
    json_output: bool,
    total_ports: int
) -> None:
    """
    Display scan results.

    Args:
        host: Target host
        open_ports: List of open ports
        duration: Scan duration in seconds
        json_output: Whether to output JSON
        total_ports: Total number of ports scanned
    """
    if json_output:
        # JSON output
        result = {
            "target": host,
            "timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": round(duration, 2),
            "total_ports_scanned": total_ports,
            "open_ports": open_ports,
            "open_ports_count": len(open_ports)
        }
        console.print(json.dumps(result, indent=2))
    else:
        # Rich formatted output
        console.print()

        if open_ports:
            # Create results table
            table = Table(title=f"Open Ports on {host}")
            table.add_column("Port", style="cyan", no_wrap=True)
            table.add_column("Status", style="green")
            table.add_column("Service", style="yellow")

            for port in open_ports:
                service = _get_common_service_name(port)
                table.add_row(str(port), "OPEN", service)

            console.print(table)
        else:
            console.print(f"[yellow]No open ports found on {host}[/yellow]")

        # Summary panel
        summary_text = (
            f"Target: {host}\n"
            f"Duration: {duration:.2f} seconds\n"
            f"Ports Scanned: {total_ports}\n"
            f"Open Ports Found: {len(open_ports)}"
        )

        panel = Panel(
            summary_text,
            title="Scan Summary",
            border_style="blue"
        )
        console.print(panel)


def _get_common_service_name(port: int) -> str:
    """
    Get common service name for well-known ports.

    Args:
        port: Port number

    Returns:
        Service name or empty string
    """
    common_services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    return common_services.get(port, "")


def show_banner() -> None:
    """Display application banner."""
    banner_text = """
    ==============================
      TCP Port Scanner v1.0.0
    ==============================
    """

    banner_panel = Panel(
        Text(banner_text, justify="center", style="bold blue"),
        border_style="blue"
    )
    console.print(banner_panel)
    console.print("[dim]Professional TCP Port Scanner for Security Assessments[/dim]\n")


@app.command()
def version() -> None:
    """Show version information."""
    console.print("TCP Port Scanner v1.0.0")
    console.print("Built with Python Typer and Rich")


if __name__ == "__main__":
    app()