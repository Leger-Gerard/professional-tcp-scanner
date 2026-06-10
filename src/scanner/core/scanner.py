"""
Core TCP port scanning functionality.
"""
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

MIN_PORT = 1
MAX_PORT = 65535
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 30.0
MIN_THREADS = 1
MAX_THREADS = 1000


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
    host = host.strip()

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
        labels = host.split(".")
        if any(len(label) > 63 for label in labels):
            raise ValueError(f"Invalid hostname format: {host}")
        if any(label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError(f"Invalid hostname format: {host}")
        return host


def validate_port(port: int) -> int:
    """Validate a single TCP port number."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError(f"Invalid port number: {port}")
    if not (MIN_PORT <= port <= MAX_PORT):
        raise ValueError(f"Port must be between {MIN_PORT}-{MAX_PORT}: {port}")
    return port


def validate_timeout(timeout: float) -> float:
    """Validate connection timeout bounds."""
    if timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
        raise ValueError(f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    return timeout


def validate_max_threads(max_threads: int) -> int:
    """Validate scanner concurrency bounds."""
    if not isinstance(max_threads, int) or isinstance(max_threads, bool):
        raise ValueError(f"Threads must be an integer between {MIN_THREADS} and {MAX_THREADS}")
    if max_threads < MIN_THREADS or max_threads > MAX_THREADS:
        raise ValueError(f"Threads must be between {MIN_THREADS} and {MAX_THREADS}")
    return max_threads


def validate_ports(ports: List[int]) -> List[int]:
    """Validate and sort a collection of TCP ports."""
    if not ports:
        return []
    return sorted({validate_port(port) for port in ports})


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

                validate_port(start_port)
                validate_port(end_port)

                if start_port > end_port:
                    raise ValueError(f"Start port must be <= end port: {part}")

                ports.update(range(start_port, end_port + 1))
            except ValueError as e:
                # Check if this is from int() conversion failure
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port range format: {part}")
                # Re-raise other ValueErrors (like our range checks)
                raise
        else:
            # Single port
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")

            ports.add(validate_port(port))

    if not ports:
        raise ValueError("No valid ports specified")

    return sorted(list(ports))


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    """Open an IPv4 or IPv6 TCP connection with a bounded timeout."""
    return socket.create_connection((host, port), timeout=timeout)


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
    validate_port(port)
    validate_timeout(timeout)

    try:
        with _connect(host, port, timeout):
            logger.debug("Port %s on %s: OPEN", port, host)
            return True
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {host}: {e}")
        return False
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        logger.debug("Port %s on %s: CLOSED/FILTERED (%s)", port, host, e)
        return False
    except Exception as e:
        logger.error(f"Unexpected error scanning port {port} on {host}: {e}")
        return False


def scan_tcp_port_with_banner(host: str, port: int, timeout: float = 0.5) -> Tuple[bool, Optional[str]]:
    """
    Scan a single TCP port and attempt to grab service banner if open.

    Args:
        host: Target hostname or IP address
        port: Port number to scan (1-65535)
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (is_open, banner_data) where banner_data is None if no banner
        could be retrieved or if port is closed
    """
    validate_port(port)
    validate_timeout(timeout)

    try:
        with _connect(host, port, timeout) as sock:
            banner = _grab_banner(sock, port, timeout)
            logger.debug(
                "Port %s on %s: OPEN%s",
                port,
                host,
                f" - Banner: {banner[:50]}" if banner else "",
            )
            return True, banner
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {host}: {e}")
        return False, None
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        logger.debug("Port %s on %s: CLOSED/FILTERED (%s)", port, host, e)
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error scanning port {port} on {host}: {e}")
        return False, None


def _decode_and_truncate_banner(banner_data: bytes, max_length: int = 512) -> Optional[str]:
    if not banner_data:
        return None

    try:
        decoded = banner_data.decode("utf-8")
    except UnicodeDecodeError:
        decoded = banner_data.decode("latin-1", errors="replace")

    truncation_suffix = "... [truncated]"
    if max_length > len(truncation_suffix) and len(decoded) > max_length:
        decoded = decoded[: max_length - len(truncation_suffix)] + truncation_suffix

    return decoded


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> Optional[str]:
    """
    Attempt to grab banner from connected socket based on port/service.

    Args:
        sock: Connected socket
        port: Port number
        timeout: Timeout for banner reading

    Returns:
        Banner string if retrieved, None otherwise
    """
    banner_data = b""

    try:
        # Set shorter timeout for banner read to avoid hanging
        banner_timeout = min(timeout, 3.0)
        sock.settimeout(banner_timeout)

        # Protocol-specific probing
        try:
            # First, try to receive any immediate banner (services like SSH, SMTP, FTP often send banners immediately)
            try:
                immediate_data = sock.recv(1024)
                banner_data += immediate_data
            except socket.timeout:
                pass  # No immediate banner

            # Send protocol-specific probes if needed
            if port in [80, 8080, 8000, 8888, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089]:  # HTTP variants
                try:
                    sock.sendall(
                        b"HEAD / HTTP/1.1\r\n"
                        b"Host: localhost\r\n"
                        b"User-Agent: port-scanner/1.0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass  # Ignore send errors
            elif port == 21:  # FTP
                # FTP usually sends banner immediately, already captured above
                pass
            elif port == 22:  # SSH
                # SSH usually sends banner immediately, already captured above
                pass
            elif port == 25:  # SMTP
                # SMTP usually sends banner immediately, already captured above
                pass
            elif port == 110:  # POP3
                # POP3 usually sends banner immediately, already captured above
                pass
            elif port == 143:  # IMAP
                # IMAP usually sends banner immediately, already captured above
                pass
            elif port == 3306:  # MySQL
                # MySQL sends initial handshake packet
                pass
            elif port == 5432:  # PostgreSQL
                # PostgreSQL expects startup packet, skip for simplicity
                pass
            elif port == 6379:  # Redis
                try:
                    sock.sendall(b"INFO\r\n")
                except OSError:
                    pass
            elif port == 27017:  # MongoDB
                # MongoDB expects specific binary protocol, skip for simplicity
                pass

            # Try to read response after probe
            try:
                response = sock.recv(1024)
                banner_data += response
            except socket.timeout:
                pass  # No further data

        except (OSError, socket.timeout) as e:
            logger.debug(f"Error during banner probing for port {port}: {e}")

        # Decode banner safely
        if banner_data:
            return _decode_and_truncate_banner(banner_data)

        return None

    except (OSError, socket.timeout) as e:
        logger.debug(f"Banner grab failed for port {port}: {e}")
        return None


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
    validated_ports = validate_ports(ports)
    validate_timeout(timeout)
    validate_max_threads(max_threads)
    logger.info(f"Starting scan of {validated_host} on {len(ports)} ports "
                f"(timeout={timeout}s, max_threads={max_threads})")

    open_ports: List[int] = []

    # Use ThreadPoolExecutor for controlled concurrency
    with ThreadPoolExecutor(max_workers=min(max_threads, len(validated_ports))) as executor:
        # Submit all scan tasks
        future_to_port = {
            executor.submit(scan_tcp_port, validated_host, port, timeout): port
            for port in validated_ports
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


def scan_ports_with_banner(
    host: str,
    ports: List[int],
    timeout: float = 0.5,
    max_threads: int = 100
) -> List[dict]:
    """
    Scan multiple ports concurrently and attempt to grab banners from open ports.

    Args:
        host: Target hostname or IP address
        ports: List of port numbers to scan
        timeout: Connection timeout in seconds
        max_threads: Maximum number of concurrent threads

    Returns:
        List of dictionaries containing port information:
        [{"port": int, "status": str, "service": str, "banner": str}, ...]
    """
    if not ports:
        return []

    # Validate host
    validated_host = validate_ip_address(host)
    validated_ports = validate_ports(ports)
    validate_timeout(timeout)
    validate_max_threads(max_threads)
    logger.info(f"Starting banner grab scan of {validated_host} on {len(ports)} ports "
                f"(timeout={timeout}s, max_threads={max_threads})")

    results: List[dict] = []

    # Import here to avoid circular imports
    from scanner.services.service_detector import get_service_name

    # Use ThreadPoolExecutor for controlled concurrency
    with ThreadPoolExecutor(max_workers=min(max_threads, len(validated_ports))) as executor:
        # Submit all scan tasks with banner grabbing
        future_to_port = {
            executor.submit(scan_tcp_port_with_banner, validated_host, port, timeout): port
            for port in validated_ports
        }

        # Process results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open, banner = future.result()
                if is_open:
                    service = get_service_name(port)
                    results.append({
                        "port": port,
                        "status": "open",
                        "service": service or "unknown",
                        "banner": banner or ""
                    })
                    logger.info(f"Port {port} is OPEN on {validated_host} "
                               f"{'- Service: ' + (service or 'unknown')}"
                               f"{'- Banner: ' + str(banner)[:50] if banner else ''}")
                else:
                    logger.debug(f"Port {port} is CLOSED on {validated_host}")
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")

    logger.info(f"Banner grab scan completed. Found {len(results)} open ports with banner info")
    return sorted(results, key=lambda x: x["port"])
