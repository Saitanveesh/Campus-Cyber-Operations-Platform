from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class CyberbitConfig:
    base_url: str = os.environ.get("CAMPUS_OPS_CYBERBIT_URL", "")
    token: str = os.environ.get("CAMPUS_OPS_CYBERBIT_TOKEN", "")
    health_path: str = os.environ.get("CAMPUS_OPS_CYBERBIT_HEALTH_PATH", "/api/health")
    hosts_path: str = os.environ.get("CAMPUS_OPS_CYBERBIT_HOSTS_PATH", "/api/hosts")


class CyberbitAdapter:
    """Narrow configurable REST adapter; concrete paths remain provider-configurable."""

    def __init__(self, config: CyberbitConfig | None = None) -> None:
        self.config = config or CyberbitConfig()

    @property
    def configured(self) -> bool:
        return bool(self.config.base_url and self.config.token)

    def _request(self, path: str) -> Any:
        if not self.configured:
            raise RuntimeError("Cyberbit adapter is not configured")
        request = urllib.request.Request(
            self.config.base_url.rstrip("/") + path,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/json",
                "User-Agent": "CampusCyberOperationsPlatform/0.3",
            },
        )
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}

    def status(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "configured": False,
                "reachable": False,
                "detail": "Cyberbit URL/token not configured",
            }
        try:
            payload = self._request(self.config.health_path)
        except (OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            return {"configured": True, "reachable": False, "detail": str(exc)}
        return {"configured": True, "reachable": True, "detail": "provider responded", "payload": payload}

    def hosts(self) -> list[dict[str, Any]]:
        if not self.configured:
            return []
        try:
            payload = self._request(self.config.hosts_path)
        except (OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError):
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            items = payload.get("hosts") or payload.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []
