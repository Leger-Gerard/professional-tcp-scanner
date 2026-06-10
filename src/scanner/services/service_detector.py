"""
Service detection module for identifying services based on port numbers.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class ServiceDetector:
    """
    Detects service names based on well-known port numbers.

    This class provides a simple mapping-based approach to service detection.
    It does not perform any network probing or banner grabbing - it simply
    maps port numbers to their commonly associated service names.
    """

    def __init__(self):
        """Initialize the service detector with port-service mappings."""
        self._port_service_map = self._build_port_service_map()
        logger.debug("ServiceDetector initialized with %d port mappings",
                    len(self._port_service_map))

    def _build_port_service_map(self) -> Dict[int, str]:
        """
        Build the port to service name mapping.

        Returns:
            Dictionary mapping port numbers to service names
        """
        return {
            # File Transfer
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "Telnet",

            # Email
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",

            # Web
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            8000: "HTTP-Alt",
            8888: "HTTP-Alt",

            # Name Resolution
            53: "DNS",
            123: "NTP",

            # Network Services
            67: "DHCP-Server",
            68: "DHCP-Client",
            161: "SNMP",
            162: "SNMP-Trap",
            389: "LDAP",
            636: "LDAPS",

            # Databases
            1433: "MSSQL",
            1434: "MSSQL-Monitor",
            1521: "Oracle",
            3306: "MySQL",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
            9300: "Elasticsearch-Transport",

            # Remote Access
            3389: "RDP",
            5901: "VNC-1",
            5902: "VNC-2",

            # Authentication
            88: "Kerberos",
            464: "Kerberos-ChangePass",

            # File Sharing
            135: "MSRPC",
            139: "NetBIOS",
            445: "SMB",
            2049: "NFS",

            # VoIP & Collaboration
            5060: "SIP",
            5061: "SIPS",
            5222: "XMPP",
            5223: "XMPP-SSL",

            # Monitoring & Management
            514: "Syslog",
            8890: "HTTPS-Proxy-Admin",

            # Gaming
            25565: "Minecraft",
            27015: "Source-Engine",
            27016: "Source-Engine",
            27018: "Source-Engine",
            27019: "Source-Engine",
            27020: "Source-Engine",
        }

    def get_service_name(self, port: int) -> str:
        """
        Get the service name associated with a port number.

        Args:
            port: Port number (1-65535)

        Returns:
            Service name string, or empty string if not found
        """
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.warning("Invalid port number provided for service detection: %s", port)
            return ""

        service_name = self._port_service_map.get(port, "")
        logger.debug("Port %d -> service: %s", port, service_name or "unknown")
        return service_name

    def get_known_ports(self) -> list[int]:
        """
        Get a list of all known port numbers in the detector.

        Returns:
            Sorted list of known port numbers
        """
        return sorted(list(self._port_service_map.keys()))

    def get_service_count(self) -> int:
        """
        Get the number of service mappings available.

        Returns:
            Number of port-service mappings
        """
        return len(self._port_service_map)


# Global instance for convenience
_service_detector = ServiceDetector()


def get_service_name(port: int) -> str:
    """
    Get the service name associated with a port number.
    Convenience function that uses the global service detector instance.

    Args:
        port: Port number (1-65535)

    Returns:
        Service name string, or empty string if not found
    """
    return _service_detector.get_service_name(port)
