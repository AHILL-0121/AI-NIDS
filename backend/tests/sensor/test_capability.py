from dataclasses import replace
from types import SimpleNamespace

import pytest

from nids.sensor.capability import CAP_NET_RAW_BIT, Probes, check_capture
from nids.sensor.interfaces import InterfaceInfo, interface_from_scapy, sort_interfaces


def probes(system: str, **overrides: object) -> Probes:
    base = Probes(
        system=lambda: system,
        module_available=lambda name: name == "scapy",
        find_library=lambda name: "libpcap.so.0.8",
        is_root=lambda: False,
        linux_cap_effective=lambda: 0,
        npcap_installed=lambda: True,
        windows_is_admin=lambda: True,
        bpf_readable=lambda: True,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def statuses(report: object) -> dict[str, str]:
    return {c.name: c.status for c in report.checks}  # type: ignore[attr-defined]


def test_linux_without_cap_net_raw_cannot_capture() -> None:
    report = check_capture(probes("Linux"))

    assert not report.ok and report.backend is None
    assert statuses(report)["privileges"] == "error"
    assert "setcap" in next(c.fix for c in report.checks if c.name == "privileges")  # type: ignore[operator]


def test_linux_with_cap_net_raw_uses_scapy_without_nfstream() -> None:
    report = check_capture(probes("Linux", linux_cap_effective=lambda: 1 << CAP_NET_RAW_BIT))

    assert report.ok and report.backend == "scapy"
    assert statuses(report)["nfstream"] == "warning"


def test_linux_as_root_with_nfstream_prefers_nfstream() -> None:
    report = check_capture(probes("Linux", is_root=lambda: True, module_available=lambda _: True))

    assert report.ok and report.backend == "nfstream"


def test_linux_without_libpcap() -> None:
    report = check_capture(probes("Linux", is_root=lambda: True, find_library=lambda _: None))

    assert statuses(report)["libpcap"] == "error" and not report.ok


def test_windows_without_npcap_explains_the_install() -> None:
    report = check_capture(probes("Windows", npcap_installed=lambda: False))

    assert not report.ok
    npcap = next(c for c in report.checks if c.name == "npcap")
    assert npcap.fix is not None and "WinPcap API-compatible" in npcap.fix


def test_windows_non_admin_is_only_a_warning() -> None:
    report = check_capture(probes("Windows", windows_is_admin=lambda: False))

    assert report.ok and report.backend == "scapy"
    assert statuses(report)["privileges"] == "warning"


def test_missing_scapy_is_an_error_everywhere() -> None:
    report = check_capture(probes("Darwin", module_available=lambda _: False))

    assert statuses(report)["scapy"] == "error" and not report.ok


def test_unknown_platform() -> None:
    assert not check_capture(probes("Plan9")).ok


def test_report_serialises_ok_for_the_api() -> None:
    assert check_capture(probes("Windows")).model_dump()["ok"] is True


@pytest.mark.parametrize(
    ("label", "description", "ips", "loopback"),
    [
        ("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", {4: ["192.168.1.20"], 6: []}, False),
        ("Loopback Pseudo-Interface 1", "Adapter for loopback traffic capture", {4: []}, True),
        ("lo", "lo", {4: ["127.0.0.1"]}, True),
    ],
)
def test_interface_from_scapy(
    label: str, description: str, ips: dict[int, list[str]], loopback: bool
) -> None:
    iface = SimpleNamespace(
        name=label, network_name=r"\Device\NPF_{X}", description=description, ips=ips, mac="aa:bb"
    )

    info = interface_from_scapy(iface)

    assert info.label == label and info.name == r"\Device\NPF_{X}"
    assert info.loopback is loopback


def test_interfaces_with_a_real_address_come_first() -> None:
    def info(label: str, ipv4: list[str], loopback: bool = False) -> InterfaceInfo:
        return InterfaceInfo(
            name=label,
            label=label,
            description=label,
            ipv4=ipv4,
            ipv6=[],
            mac=None,
            loopback=loopback,
        )

    ordered = sort_interfaces(
        [
            info("Loopback", ["127.0.0.1"], loopback=True),
            info("Bluetooth", ["169.254.16.19"]),
            info("Wi-Fi", ["192.168.1.20"]),
        ]
    )

    assert [i.label for i in ordered] == ["Wi-Fi", "Bluetooth", "Loopback"]
