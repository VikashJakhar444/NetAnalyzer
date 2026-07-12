"""
Utility Helpers Module.
Provides adapter auto-detection, formatting utilities, and shell utility wrappers.
Supports both IPv4 and IPv6.
"""
import ipaddress
import socket
import sys
from datetime import datetime
from typing import Tuple, Optional
import psutil

from core.logger import logger


def get_ip_version(ip_str: str) -> Optional[int]:
    """Return 4 for IPv4, 6 for IPv6, None if invalid."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return 4
    except ipaddress.AddressValueError:
        pass
    try:
        ipaddress.IPv6Address(ip_str.strip())
        return 6
    except ipaddress.AddressValueError:
        return None


def is_ipv6(ip_str: str) -> bool:
    return get_ip_version(ip_str) == 6


def format_bytes(size_in_bytes: int) -> str:
    """
    Formats a byte size into a human-readable string (KB, MB, GB, etc.).
    """
    if not isinstance(size_in_bytes, int) or size_in_bytes < 0:
        return "0 B"
    size = float(size_in_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_time(dt: Optional[datetime] = None) -> str:
    """
    Converts datetime to standardized ISO string. Defaults to current time.
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_default_interface(version: int = 4) -> Tuple[str, str]:
    """
    Detects the active default network interface name and local IP.
    Returns (interface_name, ip_address).
    version=4 for IPv4, version=6 for IPv6.
    """
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    target = ("8.8.8.8", 80) if version == 4 else ("2001:4860:4860::8888", 80)
    fallback_ip = "127.0.0.1" if version == 4 else "::1"
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(target)
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        logger.warning(f"Failed to detect v{version} outbound IP: {e}")
        return "Loopback", fallback_ip

    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                if addr.family == family and addr.address == local_ip:
                    stats = psutil.net_if_stats().get(interface_name)
                    if stats and stats.isup:
                        logger.info(f"Auto-detected v{version} interface: {interface_name} ({local_ip})")
                        return interface_name, local_ip
    except Exception as e:
        logger.error(f"Error mapping interface address using psutil: {e}")

    return f"Interface-v{version}", local_ip


def get_local_subnet(version: int = 4) -> str:
    """
    Calculates the CIDR subnet range for the default adapter of the given IP version.
    """
    _, local_ip = get_default_interface(version)
    fallback_v4 = "192.168.1.0/24"
    fallback_v6 = "fd00::/64"
    if version == 4:
        if local_ip == "127.0.0.1":
            return "127.0.0.1/32"
        try:
            for _, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        netmask = addr.netmask
                        if netmask:
                            bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                            ip_parts = list(map(int, local_ip.split('.')))
                            mask_parts = list(map(int, netmask.split('.')))
                            net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                            network_ip = ".".join(map(str, net_parts))
                            cidr = f"{network_ip}/{bits}"
                            logger.info(f"Auto-detected v4 subnet: {cidr}")
                            return cidr
        except Exception as e:
            logger.error(f"Failed to calculate v4 subnet: {e}")
        octets = local_ip.split('.')
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        return fallback_v4
    else:
        if local_ip == "::1":
            return "::1/128"
        try:
            addr_obj = ipaddress.IPv6Address(local_ip)
            # Typically /64 for IPv6 subnets
            cidr = f"{addr_obj.network_address}/64" if hasattr(addr_obj, 'network_address') else f"{local_ip}/64"
            # Build proper network address
            network = ipaddress.IPv6Network(f"{local_ip}/64", strict=False)
            cidr = str(network)
            logger.info(f"Auto-detected v6 subnet: {cidr}")
            return cidr
        except Exception as e:
            logger.error(f"Failed to calculate v6 subnet: {e}")
            return fallback_v6
