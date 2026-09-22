"""Settings the user can change from the UI (audit SEC-02, API-07).

Only the fields declared here can be changed through the API, each with a range. `apply` says
when a change takes effect: "restart" = the next time the sensor starts, "live" = immediately.
Paths (model files, directories) are deliberately not here: models are chosen by registered
version, never by path (audit SEC-03).
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _field(default: Any, apply: Literal["live", "restart"], description: str, **kw: Any) -> Any:
    return Field(default, description=description, json_schema_extra={"apply": apply}, **kw)


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    scan_window_s: float = _field(30.0, "restart", "Port scan / sweep time window", ge=5, le=600)
    scan_min_ports: int = _field(
        25, "restart", "Ports on one host to call it a scan", ge=5, le=5000
    )
    sweep_min_hosts: int = _field(
        20, "restart", "Hosts in one subnet to call it a sweep", ge=5, le=5000
    )
    flood_min_syn_rate: float = _field(
        100.0, "restart", "SYNs/s floor for a SYN flood", ge=10, le=1e7
    )
    flood_min_pps: float = _field(
        5000.0, "restart", "Packets/s floor for a UDP/ICMP flood", ge=100, le=1e8
    )
    flood_z: float = _field(
        6.0, "restart", "Standard deviations above normal for a flood", ge=2, le=50
    )
    allowed_protocols: list[int] = _field(
        [1, 2, 6, 17, 58], "restart", "IP protocols that never alert"
    )
    dedup_window_s: float = _field(
        900.0, "restart", "Merge repeats of an alert within this window", ge=60, le=86400
    )
    flow_sample_rate: float = _field(1.0, "restart", "Share of flows stored", ge=0, le=1)
    attack_threshold: float | None = _field(
        None, "restart", "Classifier threshold (None = model default)", ge=0, le=1
    )
    novelty_threshold: float | None = _field(
        None, "restart", "Novelty threshold (None = model default)", ge=0.5, le=1
    )
    retention_flows_days: float = _field(7.0, "live", "Keep flows this long", gt=0, le=3650)
    retention_alerts_days: float = _field(90.0, "live", "Keep alerts this long", gt=0, le=3650)
    pseudonymize_ips: bool = _field(False, "restart", "Store IP addresses as keyed hashes")

    @field_validator("allowed_protocols")
    @classmethod
    def _protocols(cls, value: list[int]) -> list[int]:
        if any(not 0 <= p <= 255 for p in value):
            raise ValueError("IP protocol numbers are 0-255")
        return sorted(set(value))

    @classmethod
    def apply_modes(cls) -> dict[str, str]:
        modes: dict[str, str] = {}
        for name, field in cls.model_fields.items():
            extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
            modes[name] = str(extra.get("apply", "restart"))
        return modes
