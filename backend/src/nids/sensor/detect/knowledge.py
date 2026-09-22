"""What each alert type means: title, MITRE ATT&CK technique, plain-language explanation and
recommendation. The wording builds on v1's alert explanations (audit §5) and adds the specifics
from each detection's evidence."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from nids.core.schemas.alert import Detection


@dataclass(frozen=True)
class AlertKind:
    title: str
    mitre: str | None
    explain: Callable[[Detection], str]
    recommend: str


def _e(d: Detection, key: str, default: Any = "?") -> Any:
    return d.evidence.get(key, default)


KINDS: dict[str, AlertKind] = {
    "port_scan": AlertKind(
        title="Port scan",
        mitre="T1046 Network Service Discovery",
        explain=lambda d: (
            f"{d.src} tried {_e(d, 'distinct_ports')} different ports on {d.dst} within "
            f"{_e(d, 'window_s')} seconds. Probing many ports quickly is how an attacker maps "
            "which services are open before trying to use them."
        ),
        recommend=(
            "Check whether the source is a device that's supposed to scan (an IT or security "
            "tool). If not, find it on your network, check it for malware, and consider "
            "blocking it."
        ),
    ),
    "host_sweep": AlertKind(
        title="Host sweep",
        mitre="T1018 Remote System Discovery",
        explain=lambda d: (
            f"{d.src} contacted {_e(d, 'distinct_hosts')} different machines on "
            f"{_e(d, 'service')} within {_e(d, 'window_s')} seconds, looking for machines that "
            "run that service."
        ),
        recommend=(
            "Printers, NAS boxes and management tools sometimes do this during discovery. If the "
            "source isn't one of those, investigate it: worms spread exactly this way."
        ),
    ),
    "syn_flood": AlertKind(
        title="SYN flood",
        mitre="T1498.001 Network Denial of Service: Direct Network Flood",
        explain=lambda d: (
            f"{d.dst} received {_e(d, 'rate')} new TCP connection attempts per second "
            f"(normal for it: about {_e(d, 'baseline')}), from {_e(d, 'distinct_sources')} "
            "source(s). Half-open connections fill the server's connection table and can make it "
            "unreachable."
        ),
        recommend=(
            "Enable SYN cookies or connection rate limiting on the target or your router. If it "
            "continues, block the sources or ask your ISP to filter upstream."
        ),
    ),
    "ddos": AlertKind(
        title="Distributed denial of service",
        mitre="T1498 Network Denial of Service",
        explain=lambda d: (
            f"{d.dst} is receiving {_e(d, 'rate')} {_e(d, 'metric')} per second from "
            f"{_e(d, 'distinct_sources')} different sources, far above its normal "
            f"{_e(d, 'baseline')}. Many sources at once is the signature of a distributed attack."
        ),
        recommend=(
            "Blocking individual sources won't keep up. Rate-limit at the edge and contact your "
            "ISP or DDoS protection provider; floods from many sources are best filtered upstream."
        ),
    ),
    "flood": AlertKind(
        title="Traffic flood",
        mitre="T1498.001 Network Denial of Service: Direct Network Flood",
        explain=lambda d: (
            f"{d.dst} is receiving {_e(d, 'rate')} {_e(d, 'metric')} per second (normal for it: "
            f"about {_e(d, 'baseline')}) and is answering almost none of them "
            f"(reply ratio {_e(d, 'reply_ratio')})."
        ),
        recommend="Rate-limit or block the source at your router or firewall.",
    ),
    "unusual_protocol": AlertKind(
        title="Unusual protocol",
        mitre="T1095 Non-Application Layer Protocol",
        explain=lambda d: (
            f"{d.src} sent IP protocol {d.protocol} ({_e(d, 'protocol_name', 'unknown')}) to "
            f"{d.dst}. That protocol isn't on this network's allow-list, and malware sometimes "
            "uses unusual protocols to hide its traffic."
        ),
        recommend=(
            "If this is a VPN, tunnel or routing protocol you use, add it to the allow-list in "
            "Settings. Otherwise, check what's running on the source."
        ),
    ),
    "ml_known_attack": AlertKind(
        title="Known attack pattern",
        mitre=None,  # set per family below
        explain=lambda d: (
            f"The traffic from {d.src} to {d.dst} closely matches {_e(d, 'family_label')} "
            f"traffic the model was trained on (probability {_e(d, 'attack_prob')})."
        ),
        recommend=(
            "Look at the related flows to confirm. The model has only seen lab traffic, so treat "
            "this as strong evidence, not proof."
        ),
    ),
    "ml_anomaly": AlertKind(
        title="Unusual traffic",
        mitre=None,
        explain=lambda d: (
            f"This connection from {d.src} to {d.dst} is more unusual than "
            f"{_e(d, 'novelty_pct')} of normal traffic the model has learned. It doesn't match a "
            "known attack; it just doesn't look like the usual traffic."
        ),
        recommend=(
            "Check which program made the connection. Backups, updates and new software are "
            "common innocent causes; an unexplained one is worth investigating."
        ),
    ),
}

ML_FAMILIES: dict[str, tuple[str, str | None]] = {
    # family -> (human label, MITRE technique)
    "dos": ("denial-of-service", "T1499 Endpoint Denial of Service"),
    "ddos": ("distributed denial-of-service", "T1498 Network Denial of Service"),
    "recon": ("scanning / reconnaissance", "T1046 Network Service Discovery"),
    "brute_force": ("password brute-force", "T1110 Brute Force"),
    "web_attack": ("web application attack", "T1190 Exploit Public-Facing Application"),
    "botnet": ("botnet command-and-control", "T1071 Application Layer Protocol"),
    "infiltration": ("infiltration", None),
    "exploit": ("exploit", "T1190 Exploit Public-Facing Application"),
    "other": ("attack", None),
}


def describe(d: Detection) -> tuple[str, str | None, str, str]:
    """(title, mitre, explanation, recommendation) for a detection."""
    kind = KINDS[d.type]
    title, mitre = kind.title, kind.mitre
    if d.type == "ml_known_attack" and d.family:
        label, mitre = ML_FAMILIES.get(d.family, (d.family, None))
        title = f"Looks like {label}"
    return title, mitre, kind.explain(d), kind.recommend
