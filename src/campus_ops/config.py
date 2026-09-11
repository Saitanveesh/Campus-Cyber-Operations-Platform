from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    network_poll_seconds: float = 3.0
    tool_probe_seconds: float = 30.0
    interface_switch_margin: int = 15
    interface_confirmations: int = 2


DEFAULT_SETTINGS = Settings()
