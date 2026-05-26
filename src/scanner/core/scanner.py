"""
Core TCP port scanning functionality.
"""
import socket
import ipaddress
import logging
from typing import List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


def validate_ip_address(host: str) -> str:
    """
    Validate and normalize host input (IP address or hostname).

    Args:
        host: IP address or hostname to validate

    Returns:
        Normalized host string

    Raises:
        ValueError: If host is invalid
    """
    try:
        # Try to parse as IP address first
        ipaddress.ip_address(host)
        return host
    except ValueError:
        # If not an IP, treat as hostname (basic validation)
        if not host or len(host) > 255:
            raise ValueError(f"Invalid hostname: {host}")
        # Basic hostname validation (letters, digits, hyphens, dots)
        if not all(c.isalnum() or c in '.-' for c in host):
            raise ValueError(f"Invalid hostname format: {host}")
        # Additional hostname validation: no consecutive dots, no leading/trailing dots
        if '..' in host or host.startswith('.') or host.endswith('.'):
            raise ValueError(f"Invalid hostname format: {host}")
        # At least one alphanumeric character
        if not any(c.isalnum() for c in host):
            raise ValueError(f"Invalid hostname format: {host}")
        return host


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port specification string into list of port numbers.

    Supports formats:
    - Single port: "80"
    - Comma separated: "80,443,8080"
    - Range: "1-1000"
    - Mixed: "80,443,8000-9000"

    Args:
        port_string: Port specification string

    Returns:
        Sorted list of unique port numbers

    Raises:
        ValueError: If port specification is invalid
    """
    if not port_string.strip():
        raise ValueError("Port specification cannot be empty")

    parts = port_string.split(',')
    # Check for empty parts (leading, trailing, or double commas)
    for part in parts:
        if not part.strip():
            raise ValueError("Empty port specification detected")

    ports: Set[int] = set()

    for part in parts:
        part = part.strip()
        if not part:
            continue  # This shouldn't happen due to the check above, but kept for safety

        if '-' in part:
            # Port range
            try:
                start_str, end_str = part.split('-', 1)
                start_port = int(start_str.strip())
                end_port = int(end_str.strip())

                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    raise ValueError(f"Ports must be between 1-65535: {part}")

                if start_port > end_port:
                    raise ValueError(f"Start port must be <= end port: {part}")

                ports.update(range(start_port, end_port + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port range format: {part}")
                raise
        else:
            # Single port
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port must be between 1-65535: {port}")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")

    if not ports:
        raise ValueError("No valid ports specified")

    return sorted(list(ports))


def scan_tcp_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Scan a single TCP port on the target host.

    Args:
        host: Target hostname or IP address
        port: Port number to scan (1-65535)
        timeout: Connection timeout in seconds

    Returns:
        True if port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            is_open = result == 0
            logger.debug(f"Port {port} on {host}: {'OPEN' if is_open else 'CLOSED'} (result={result})")
            return is_open
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {host}: {e}")
        return False
    except socket.error as e:
        logger.debug(f"Socket error scanning port {port} on {host}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error scanning port {port} on {host}: {e}")
        return False


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 0.5,
    max_threads: int = 100
) -> List[int]:
    """
    Scan multiple ports concurrently using thread pool.

    Args:
        host: Target hostname or IP address
        ports: List of port numbers to scan
        timeout: Connection timeout in seconds
        max_threads: Maximum number of concurrent threads

    Returns:
        Sorted list of open port numbers
    """
    if not ports:
        return []

    # Validate host
    validated_host = validate_ip_address(host)
    logger.info(f"Starting scan of {validated_host} on {len(ports)} ports "
                f"(timeout={timeout}s, max_threads={max_threads})")

    open_ports: List[int] = []

    # Use ThreadPoolExecutor for controlled concurrency
    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        # Submit all scan tasks
        future_to_port = {
            executor.submit(scan_tcp_port, validated_host, port, timeout): port
            for port in ports
        }

        # Process results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
                    logger.info(f"Port {port} is OPEN on {validated_host}")
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")

    logger.info(f"Scan completed. Found {len(open_ports)} open ports: {sorted(open_ports)}")
    return sorted(open_ports)