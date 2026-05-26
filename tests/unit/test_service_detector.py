"""
Unit tests for service detector module.
"""
import logging
from unittest.mock import patch

import pytest

from scanner.services.service_detector import ServiceDetector, get_service_name


def test_service_detector_initialization():
    """Test that ServiceDetector initializes correctly."""
    detector = ServiceDetector()
    assert detector is not None
    assert detector.get_service_count() > 0


def test_get_service_name_known_ports():
    """Test service name lookup for known ports."""
    detector = ServiceDetector()

    # Test some common ports
    assert detector.get_service_name(22) == "SSH"
    assert detector.get_service_name(80) == "HTTP"
    assert detector.get_service_name(443) == "HTTPS"
    assert detector.get_service_name(3306) == "MySQL"
    assert detector.get_service_name(5432) == "PostgreSQL"


def test_get_service_name_unknown_ports():
    """Test that unknown ports return empty string."""
    detector = ServiceDetector()

    # Test some uncommon ports
    assert detector.get_service_name(12345) == ""
    assert detector.get_service_name(50000) == ""
    assert detector.get_service_name(65000) == ""


def test_get_service_name_invalid_ports():
    """Test service name lookup with invalid port numbers."""
    detector = ServiceDetector()

    # Test invalid port numbers
    assert detector.get_service_name(0) == ""
    assert detector.get_service_name(-1) == ""
    assert detector.get_service_name(65536) == ""
    assert detector.get_service_name(100000) == ""


def test_get_service_name_non_integer():
    """Test service name lookup with non-integer input."""
    detector = ServiceDetector()

    # Test with string input
    assert detector.get_service_name("80") == ""
    assert detector.get_service_name(None) == ""
    assert detector.get_service_name([]) == ""


def test_get_known_ports():
    """Test getting list of known ports."""
    detector = ServiceDetector()
    known_ports = detector.get_known_ports()

    assert isinstance(known_ports, list)
    assert len(known_ports) > 0
    assert 22 in known_ports
    assert 80 in known_ports
    assert 443 in known_ports

    # Should be sorted
    assert known_ports == sorted(known_ports)


def test_get_service_count():
    """Test getting service count."""
    detector = ServiceDetector()
    count = detector.get_service_count()

    assert isinstance(count, int)
    assert count > 0


def test_global_get_service_name_function():
    """Test the global get_service_name convenience function."""
    # Test that it works and returns expected values
    assert get_service_name(22) == "SSH"
    assert get_service_name(80) == "HTTP"
    assert get_service_name(9999) == ""  # Unknown port


def test_service_detector_logging(caplog):
    """Test that ServiceDetector logs appropriately."""
    with caplog.at_level(logging.DEBUG):
        detector = ServiceDetector()
        # Should have logged initialization
        assert "ServiceDetector initialized" in caplog.text

    # Test service lookup logging
    with caplog.at_level(logging.DEBUG):
        detector.get_service_name(22)
        detector.get_service_name(9999)  # Unknown port
        # Should have logged the lookups
        assert "Port 22 -> service:" in caplog.text
        assert "Port 9999 -> service:" in caplog.text


def test_service_detector_invalid_port_logging(caplog):
    """Test that invalid ports generate warnings."""
    with caplog.at_level(logging.WARNING):
        detector = ServiceDetector()
        detector.get_service_name(-1)  # Invalid port
        detector.get_service_name(70000)  # Invalid port

        # Should have logged warnings
        assert "Invalid port number provided" in caplog.text