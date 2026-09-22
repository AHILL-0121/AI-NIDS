"""Can this machine capture packets, and with which backend? (audit CAP-03)

v1 started "Running" even when capture had failed. Here every missing piece becomes a check with a
concrete fix, and the sensor refuses to start while any check is an error.
"""

import ctypes
import ctypes.util
import importlib.util
import os
import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, computed_field

Status = Literal["ok", "warning", "error"]

CAP_NET_RAW_BIT = 13


class Check(BaseModel):
    name: str
    status: Status
    detail: str
    fix: str | None = None


class CapabilityReport(BaseModel):
    platform: str
    backend: Literal["nfstream", "scapy"] | None
    checks: list[Check]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return all(c.status != "error" for c in self.checks)


def _linux_cap_effective() -> int | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
    except (OSError, ValueError):
        pass
    return None


def _windows_is_admin() -> bool:
    windll = getattr(ctypes, "windll", None)  # Windows only; getattr keeps mypy portable
    try:
        return bool(windll.shell32.IsUserAnAdmin()) if windll else False
    except (AttributeError, OSError):
        return False


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _npcap_installed() -> bool:
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    return (system_root / "System32" / "Npcap" / "wpcap.dll").is_file()


@dataclass(frozen=True)
class Probes:
    """System lookups, injectable so every platform branch can be tested anywhere."""

    system: Callable[[], str] = platform.system
    module_available: Callable[[str], bool] = field(
        default=lambda name: importlib.util.find_spec(name) is not None
    )
    find_library: Callable[[str], str | None] = ctypes.util.find_library
    is_root: Callable[[], bool] = _is_root
    linux_cap_effective: Callable[[], int | None] = _linux_cap_effective
    npcap_installed: Callable[[], bool] = _npcap_installed
    windows_is_admin: Callable[[], bool] = _windows_is_admin
    bpf_readable: Callable[[], bool] = lambda: os.access("/dev/bpf0", os.R_OK)


def _scapy_check(p: Probes) -> Check:
    if p.module_available("scapy"):
        return Check(name="scapy", status="ok", detail="Scapy is installed.")
    return Check(
        name="scapy",
        status="error",
        detail="Scapy is not installed.",
        fix="cd backend && uv sync --extra capture",
    )


def _linux_checks(p: Probes) -> tuple[list[Check], Literal["nfstream", "scapy"]]:
    checks = [_scapy_check(p)]
    if p.find_library("pcap"):
        checks.append(Check(name="libpcap", status="ok", detail="libpcap found."))
    else:
        checks.append(
            Check(
                name="libpcap",
                status="error",
                detail="libpcap was not found.",
                fix="Install it, e.g. `sudo apt install libpcap0.8` (Debian/Ubuntu).",
            )
        )

    caps = p.linux_cap_effective()
    if p.is_root() or (caps is not None and caps >> CAP_NET_RAW_BIT & 1):
        checks.append(Check(name="privileges", status="ok", detail="Raw capture is permitted."))
    else:
        checks.append(
            Check(
                name="privileges",
                status="error",
                detail="This process lacks CAP_NET_RAW, so it can't open a capture socket.",
                fix=(
                    "Run the sensor in Docker with `cap_add: [NET_RAW, NET_ADMIN]`, or grant the "
                    "interpreter the capability: "
                    "`sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)`."
                ),
            )
        )

    if p.module_available("nfstream"):
        checks.append(Check(name="nfstream", status="ok", detail="NFStream backend available."))
        return checks, "nfstream"
    checks.append(
        Check(
            name="nfstream",
            status="warning",
            detail="NFStream is not installed; falling back to the slower Scapy backend.",
            fix="cd backend && uv sync --extra capture",
        )
    )
    return checks, "scapy"


def _windows_checks(p: Probes) -> list[Check]:
    checks = [_scapy_check(p)]
    if p.npcap_installed():
        checks.append(Check(name="npcap", status="ok", detail="Npcap is installed."))
    else:
        checks.append(
            Check(
                name="npcap",
                status="error",
                detail="Npcap is not installed, so packets can't be captured.",
                fix=(
                    "Install Npcap from https://npcap.com and tick "
                    "'Install Npcap in WinPcap API-compatible Mode'."
                ),
            )
        )
    if p.windows_is_admin():
        checks.append(Check(name="privileges", status="ok", detail="Running as Administrator."))
    else:
        checks.append(
            Check(
                name="privileges",
                status="warning",
                detail="Not running as Administrator.",
                fix=(
                    "If capture fails with an access error, Npcap was installed with "
                    "'Restrict driver access to Administrators'; run the sensor from an "
                    "elevated terminal."
                ),
            )
        )
    return checks


def _macos_checks(p: Probes) -> list[Check]:
    checks = [_scapy_check(p)]
    if p.is_root() or p.bpf_readable():
        checks.append(Check(name="bpf", status="ok", detail="/dev/bpf* is readable."))
    else:
        checks.append(
            Check(
                name="bpf",
                status="error",
                detail="/dev/bpf* is not readable by this user.",
                fix="Run with sudo, or install Wireshark's ChmodBPF helper.",
            )
        )
    return checks


def check_capture(probes: Probes | None = None) -> CapabilityReport:
    p = probes or Probes()
    system = p.system()
    backend: Literal["nfstream", "scapy"] | None
    if system == "Linux":
        checks, backend = _linux_checks(p)
    elif system == "Windows":
        checks, backend = _windows_checks(p), "scapy"
    elif system == "Darwin":
        checks, backend = _macos_checks(p), "scapy"
    else:
        checks = [Check(name="platform", status="error", detail=f"Unsupported platform: {system}.")]
        backend = None

    report = CapabilityReport(platform=system, backend=backend, checks=checks)
    if not report.ok:
        report.backend = None
    return report
