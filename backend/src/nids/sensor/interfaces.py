"""List capture interfaces with friendly names (audit CAP-03: no more hard-coded `eth0`).

On Windows the capture name is the Npcap device (`\\Device\\NPF_{GUID}`) while people know the
adapter as "Wi-Fi" or "Ethernet"; both are returned so the UI can show one and send the other.
"""

import ipaddress
from typing import Any

from pydantic import BaseModel


class InterfaceInfo(BaseModel):
    name: str  # what to pass to the capture backend
    label: str  # short friendly name ("Wi-Fi", "eth0")
    description: str
    ipv4: list[str]
    ipv6: list[str]
    mac: str | None
    loopback: bool


def _is_loopback(label: str, description: str, ipv4: list[str]) -> bool:
    if label == "lo" or "loopback" in description.lower():
        return True
    return any(ipaddress.ip_address(ip).is_loopback for ip in ipv4)


def interface_from_scapy(iface: Any) -> InterfaceInfo:
    ips = getattr(iface, "ips", {}) or {}
    ipv4 = [str(ip) for ip in ips.get(4, [])]
    ipv6 = [str(ip) for ip in ips.get(6, [])]
    label = str(iface.name)
    description = str(getattr(iface, "description", "") or label)
    return InterfaceInfo(
        name=str(getattr(iface, "network_name", None) or label),
        label=label,
        description=description,
        ipv4=ipv4,
        ipv6=ipv6,
        mac=getattr(iface, "mac", None) or None,
        loopback=_is_loopback(label, description, ipv4),
    )


def _has_routable_ipv4(info: InterfaceInfo) -> bool:
    # 169.254.x.x (link-local) means the adapter has no real network, so it doesn't count.
    return any(not ipaddress.ip_address(ip).is_link_local for ip in info.ipv4)


def sort_interfaces(infos: list[InterfaceInfo]) -> list[InterfaceInfo]:
    """Adapters with a routable IPv4 address first, then the rest, loopback last."""
    return sorted(infos, key=lambda i: (i.loopback, not _has_routable_ipv4(i), i.label.lower()))


def list_interfaces() -> list[InterfaceInfo]:
    from scapy.all import conf

    return sort_interfaces([interface_from_scapy(i) for i in conf.ifaces.values() if i.is_valid()])
