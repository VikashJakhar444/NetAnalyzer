"""
Input Validation Module.
Verifies IP addresses, MAC addresses, port numbers, and subnets.
Supports both IPv4 and IPv6.
"""
import ipaddress
import os
import re
from pathlib import Path


def _ip_version(ip_str: str):
    """Return 4, 6, or None."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        ipaddress.IPv4Address(cleaned)
        return 4
    except ipaddress.AddressValueError:
        pass
    try:
        ipaddress.IPv6Address(cleaned)
        return 6
    except ipaddress.AddressValueError:
        return None


def validate_ip(ip_str: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address."""
    return _ip_version(ip_str) is not None


def validate_ipv4(ip_str: str) -> bool:
    """Checks if a string is a valid IPv4 address."""
    return _ip_version(ip_str) == 4


def validate_ipv6(ip_str: str) -> bool:
    """Checks if a string is a valid IPv6 address."""
    return _ip_version(ip_str) == 6


def validate_mac(mac_str: str) -> bool:
    """
    Checks if a string is a valid MAC address (supports colon or hyphen separators).
    """
    if not mac_str or not isinstance(mac_str, str):
        return False
    # Standard MAC formats: 00:11:22:33:44:55, 00-11-22-33-44-55
    pattern = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
    return bool(pattern.match(mac_str.strip()))


def validate_port(port_val) -> bool:
    """
    Checks if a port number is within the valid range (1 - 65535).
    """
    try:
        port = int(port_val)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def validate_network(network_cidr: str) -> bool:
    """
    Checks if a network is a valid IPv4 or IPv6 CIDR subnet.
    """
    if not network_cidr or not isinstance(network_cidr, str):
        return False
    cleaned = network_cidr.strip()
    if "/" not in cleaned:
        return False
    try:
        ipaddress.IPv4Network(cleaned, strict=False)
        return True
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
        pass
    try:
        ipaddress.IPv6Network(cleaned, strict=False)
        return True
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
        return False


def validate_network_scope(network_cidr: str) -> bool:
    """
    Checks if a network CIDR is within private/ULAv6 ranges (defensive scope).
    """
    cleaned = network_cidr.strip()
    try:
        net = ipaddress.IPv4Network(cleaned, strict=False)
        return any(net.overlaps(allowed) for allowed in [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ])
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
        pass
    try:
        net = ipaddress.IPv6Network(cleaned, strict=False)
        return any(net.overlaps(allowed) for allowed in [
            ipaddress.IPv6Network("fd00::/8"),       # ULA (Unique Local Address)
            ipaddress.IPv6Network("fc00::/7"),       # ULA (deprecated but valid)
            ipaddress.IPv6Network("fe80::/10"),      # Link-local
        ])
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
        return False


def validate_path(path_str: str) -> bool:
    """
    Checks if a string is a valid file path that exists or can be created.
    """
    if not path_str or not isinstance(path_str, str):
        return False
    try:
        path = Path(path_str.strip())
        if path.is_dir():
            return True
        parent = path.parent
        return parent.exists() and os.access(parent, os.W_OK)
    except Exception:
        return False
