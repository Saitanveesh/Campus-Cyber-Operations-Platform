from __future__ import annotations

from datetime import UTC, datetime

from campus_ops.event_bus import EventBus
from campus_ops.models import EventKind, WorkerState
from campus_ops.state import LiveState
from campus_ops.workers.base import BaseWorker
from campus_ops.workers.intelligence import endpoint_role


_LOCAL_ASSET_ROLES = frozenset({"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"})


def _valid_unicast_mac(value: str) -> bool:
    raw = value.strip().lower().replace("-", ":")
    parts = raw.split(":")
    if len(parts) != 6:
        return False
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return False
    if any(part < 0 or part > 255 for part in octets):
        return False
    if all(part == 0 for part in octets) or all(part == 255 for part in octets):
        return False
    return (octets[0] & 1) == 0


class AssetEngineWorker(BaseWorker):
    """Publish only confirmed local assets from passive source-frame evidence.

    Internet peers and private addresses outside the selected local prefix are traffic
    peers, not inventory assets. A local address must be observed as the source of at
    least two frames with a valid unicast source MAC before it enters the Assets view.
    This deliberately trades instant discovery for a much lower false/ghost asset rate.
    """

    def __init__(self, bus: EventBus, state: LiveState, session_provider, network_provider) -> None:
        super().__init__("asset-engine", bus)
        self.state = state
        self.session_provider = session_provider
        self.network_provider = network_provider
        self._candidate_counts: dict[tuple[str, str], int] = {}
        self._candidate_session: str | None = None

    async def run(self) -> None:
        sub = await self.bus.subscribe(self.name)
        self.health.state = WorkerState.HEALTHY
        try:
            while not self.stopping:
                event = await sub.queue.get()
                session_id = self.session_provider()
                if not session_id or event.session_id != session_id:
                    continue
                if event.kind != EventKind.OBSERVATION or event.payload.get("type") != "PACKET":
                    continue
                if self._candidate_session != session_id:
                    self._candidate_session = session_id
                    self._candidate_counts.clear()

                payload = dict(event.payload)
                src_ip = str(payload.get("src_ip") or "").strip()
                src_mac = str(payload.get("eth_src") or "").strip().lower()
                if not src_ip or not _valid_unicast_mac(src_mac):
                    continue

                role = endpoint_role(src_ip, self.network_provider())
                if role not in _LOCAL_ASSET_ROLES:
                    continue

                candidate_key = (src_ip, src_mac)
                count = self._candidate_counts.get(candidate_key, 0) + 1
                self._candidate_counts[candidate_key] = count
                if count < 2:
                    self.health.heartbeat("validating local source-frame candidates")
                    continue

                now = datetime.now(UTC).isoformat()
                previous = self.state.get_asset(src_ip)
                previous_mac = str(previous.get("mac") or "").lower()
                # Do not silently merge two MAC identities behind the same IP. The most
                # recently confirmed source wins only after the new pair independently
                # satisfied the two-frame confirmation rule above.
                identity_changed = bool(previous_mac and previous_mac != src_mac)
                vendor = payload.get("eth_src_vendor") or previous.get("vendor")
                hostname = payload.get("dhcp_hostname") or previous.get("hostname")
                self.state.upsert_asset(
                    src_ip,
                    {
                        **previous,
                        "id": src_ip,
                        "ip": src_ip,
                        "mac": src_mac,
                        "vendor": vendor,
                        "role": role,
                        "classification": role,
                        "local_device": True,
                        "hostname": hostname,
                        "dhcp_hostname": hostname,
                        "vlan_id": payload.get("vlan_id") or previous.get("vlan_id"),
                        "first_seen": previous.get("first_seen", now),
                        "last_seen": now,
                        "packets_as_source": int(previous.get("packets_as_source", 0)) + 1,
                        "confirmation_frames": count,
                        "identity_changed": identity_changed,
                        "evidence": "CONFIRMED_LOCAL_SOURCE_FRAMES",
                        "confidence": "HIGH",
                    },
                )
                self.health.heartbeat(f"confirmed_assets={len(self.state.snapshot()['assets'])}")
        finally:
            await self.bus.unsubscribe(self.name)
