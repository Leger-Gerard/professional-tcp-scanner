"""
Professional CLI interface for TCP port scanner using Typer and Rich.
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

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
    scan_tcp_port,
    scan_tcp_port_with_banner
)
from scanner.services.service_detector import get_service_name

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
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for JSON report (requires --json-output)"
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
    ),
    banner_grab: bool = typer.Option(
        False,
        "--banner-grab",
        "-b",
        help="Attempt to grab service banners from open ports"
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

    # Scan with banner grabbing for service fingerprinting
    port-scanner scan --host target.com --ports 80,443,22 --banner-grab
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
            scan_results = _scan_with_progress(
                validated_host,
                port_list,
                timeout,
                threads,
                progress,
                task,
                grab_banner=banner_grab
            )

        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()

        # Display results
        _display_results(
            validated_host,
            scan_results,
            scan_duration,
            json_output,
            len(port_list),
            output,
            banner_grab=banner_grab
        )

        # Log results
        open_ports_count = len(scan_results) if isinstance(scan_results, list) else 0
        logger.info(f"Scan completed: {open_ports_count} open ports found in {scan_duration:.2f}s")

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
    task_id,
    grab_banner: bool = False
) -> Union[List[int], List[dict]]:
    """
    Scan ports with progress bar updates.

    Args:
        host: Target host
        ports: Ports to scan
        timeout: Connection timeout
        max_threads: Max concurrent threads
        progress: Rich progress instance
        task_id: Progress task ID
        grab_banner: Whether to attempt banner grabbing

    Returns:
        If grab_banner=False: List[int] (open ports)
        If grab_banner=True: List[dict] with keys: port, status, service, banner
    """
    if not ports:
        return [] if not grab_banner else []

    # Import service detector for service names
    from scanner.services.service_detector import get_service_name

    # Use ThreadPoolExecutor for controlled concurrency
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: Union[List[int], List[dict]] = []

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        # Submit all scan tasks
        future_to_port = {
            executor.submit(
                scan_tcp_port_with_banner if grab_banner else scan_tcp_port,
                host,
                port,
                timeout
            ): port
            for port in ports
        }

        # Process results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if grab_banner:
                    is_open, banner = result
                    if is_open:
                        service = get_service_name(port)
                        # For consistency with the JSON output, we'll return a dict
                        # that matches what scan_ports_with_banner returns
                        results.append({
                            "port": port,
                            "status": "open",
                            "service": service or "unknown",
                            "banner": banner or ""
                        })
                        logger = logging.getLogger(__name__)
                        logger.debug(f"Port {port} is OPEN on {host} - Service: {service or 'unknown'}")
                    else:
                        logger = logging.getLogger(__name__)
                        logger.debug(f"Port {port} is CLOSED on {host}")
                else:
                    if result:  # port is open
                        results.append(port)  # type: ignore
                        logger = logging.getLogger(__name__)
                        logger.debug(f"Port {port} is OPEN on {host}")
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Error scanning port {port}: {e}")
            finally:
                progress.update(task_id, advance=1)

    if grab_banner:
        # Sort by port number
        return sorted(results, key=lambda x: x["port"])  # type: ignore
    else:
        return sorted(open_ports)  # type: ignore


def _display_results(
    host: str,
    scan_results: Union[List[int], List[dict]],
    duration: float,
    json_output: bool,
    total_ports: int,
    output: Optional[Path] = None,
    banner_grab: bool = False
) -> None:
    """
    Display scan results.

    Args:
        host: Target host
        scan_results: Either List[int] (open ports) or List[dict] (with service/banner info)
        duration: Scan duration in seconds
        json_output: Whether to output JSON
        total_ports: Total number of ports scanned
        output: Optional file path to write JSON report
        banner_grab: Whether banner grabbing was performed
    """
    if json_output:
        # JSON output
        if banner_grab and isinstance(scan_results, list) and len(scan_results) > 0 and isinstance(scan_results[0], dict):
            # Banner grabbing results format
            result = {
                "target": host,
                "timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "total_ports_scanned": total_ports,
                "open_ports": scan_results,
                "open_ports_count": len(scan_results),
                "banner_grab_enabled": True
            }
        else:
            # Standard format
            ports_with_services = []
            for port in scan_results:  # type: ignore
                ports_with_services.append({
                    "port": port,
                    "service": get_service_name(port) or "unknown"
                })

            result = {
                "target": host,
                "timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "total_ports_scanned": total_ports,
                "open_ports": ports_with_services,
                "open_ports_count": len(ports_with_services),
                "banner_grab_enabled": banner_grab
            }
        json_str = json.dumps(result, indent=2)
        if output:
            # Ensure output directory exists
            output.parent.mkdir(parents=True, exist_ok=True)
            try:
                output.write_text(json_str)
                logger = logging.getLogger(__name__)
                logger.info(f"JSON report written to {output}")
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to write JSON report to {output}: {e}")
                console.print(f"[bold red]Error:[/bold red] Failed to write JSON report: {e}")
                raise typer.Exit(1)
        else:
            console.print(json_str)
    else:
        # Rich formatted output
        console.print()

        if banner_grab and isinstance(scan_results, list) and len(scan_results) > 0 and isinstance(scan_results[0], dict):
            # Banner grabbing results format
            if scan_results:
                # Create results table
                table = Table(title=f"Open Ports on {host}")
                table.add_column("Port", style="cyan", no_wrap=True)
                table.add_column("Status", style="green")
                table.add_column("Service", style="yellow")
                table.add_column("Banner", style="dim", max_width=40)

                for port_info in scan_results:
                    banner_display = port_info["banner"][:50] + "..." if len(port_info["banner"]) > 50 else port_info["banner"]
                    if not banner_display:
                        banner_display = "[no banner]"
                    table.add_row(
                        str(port_info["port"]),
                        port_info["status"],
                        port_info["service"],
                        banner_display
                    )

                console.print(table)
            else:
                console.print(f"[yellow]No open ports found on {host}[/yellow]")
        else:
            # Standard format
            open_ports = scan_results if isinstance(scan_results, list) else []
            if open_ports:
                # Create results table
                table = Table(title=f"Open Ports on {host}")
                table.add_column("Port", style="cyan", no_wrap=True)
                table.add_column("Status", style="green")
                table.add_column("Service", style="yellow")

                for port in open_ports:
                    service = get_service_name(port)
                    table.add_row(str(port), "OPEN", service)

                console.print(table)
            else:
                console.print(f"[yellow]No open ports found on {host}[/yellow]")

        # Summary panel
        open_ports_count = len(scan_results) if isinstance(scan_results, list) else 0
        summary_text = (
            f"Target: {host}\n"
            f"Duration: {duration:.2f} seconds\n"
            f"Ports Scanned: {total_ports}\n"
            f"Open Ports Found: {open_ports_count}"
        )

        panel = Panel(
            summary_text,
            title="Scan Summary",
            border_style="blue"
        )
        console.print(panel)




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