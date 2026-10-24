"""Conservative D100 door evidence from authenticated MiBeacon events.

An automatic lock is evidence for a separate inferred state, not a door contact.
No radio or device-control operations are performed here.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from sensor_state_data import BinarySensorDeviceClass

from .const import ExtendedBinarySensorDeviceClass
from .locks import BLE_LOCK_ACTION, BLE_LOCK_METHOD

if TYPE_CHECKING:
    from .parser import XiaomiBluetoothDeviceData

MAX_EVENT_AGE = 120
MAX_FUTURE_SKEW = 30


class D100State:
    """Track fresh evidence in memory only; never restore old door guesses."""

    def __init__(self) -> None:
        self.authenticated = False
        self.discovery = False
        self.latest = 0
        self.seen: set[tuple[int, bytes]] = set()
        self.evidence: dict[str, dict[str, Any]] = {}

    def accept(self, kind: int, value: bytes) -> bool:
        """Require fresh, ordered, authenticated events and suppress repeats."""
        if not self.authenticated or self.discovery:
            return False
        expected = 5 if kind == 0x0007 else 9
        if len(value) != expected:
            return False
        if kind == 0x0007 and value[0] not in range(6):
            return False
        if kind == 0x000B and (
            value[0] & 0x0F not in BLE_LOCK_ACTION
            or value[0] >> 4 not in BLE_LOCK_METHOD
        ):
            return False
        timestamp = int.from_bytes(value[-4:], "little")
        now = time.time()
        if not now - MAX_EVENT_AGE <= timestamp <= now + MAX_FUTURE_SKEW:
            return False
        identity = (kind, value)
        if timestamp < self.latest or identity in self.seen:
            return False
        if timestamp > self.latest:
            self.seen.clear()
        self.latest = timestamp
        self.seen.add(identity)
        return True

    def publish(
        self,
        device: XiaomiBluetoothDeviceData,
        key: str,
        value: bool | None,
        source: str,
        timestamp: int,
    ) -> None:
        """Expose state and its evidence separately from the ordinary lock."""
        if key == "door":
            device.update_predefined_binary_sensor(BinarySensorDeviceClass.DOOR, value)
        else:
            device.update_binary_sensor(
                key="door_inferred",
                native_value=value,
                device_class=BinarySensorDeviceClass.DOOR,
                name="Door inferred",
            )
        self.evidence[key] = {
            "state_source": source,
            "last_evidence_at": timestamp,
            "inferred": key == "door_inferred" and source == "automatic_lock",
        }

    def door(self, value: bytes, device: XiaomiBluetoothDeviceData) -> None:
        """Only explicit open/closed/left-open objects establish door position."""
        if not self.accept(0x0007, value):
            return
        code = value[0]
        timestamp = int.from_bytes(value[1:], "little")
        if code in (0, 1, 2):
            opened = code != 1
            source = {0: "explicit_open", 1: "explicit_close", 2: "door_left_open"}[
                code
            ]
            self.publish(device, "door", opened, source, timestamp)
            self.publish(device, "door_inferred", opened, source, timestamp)
        resets = {
            0: (("door_stuck", False), ("knock_on_the_door", False)),
            1: (("door_left_open", False), ("pry_the_door", False)),
            2: (("door_left_open", True),),
            3: (("knock_on_the_door", True),),
            4: (("pry_the_door", True),),
            5: (("door_stuck", True),),
        }
        for key, state in resets[code]:
            device.update_binary_sensor(
                key=key,
                native_value=state,
                device_class=ExtendedBinarySensorDeviceClass(key),
                name=key.replace("_", " ").capitalize(),
            )

    def lock(self, value: bytes, device: XiaomiBluetoothDeviceData) -> None:
        """Unlock invalidates a guess; only normal automatic lock infers closed."""
        action = value[0] & 0x0F
        method = value[0] >> 4
        timestamp = int.from_bytes(value[-4:], "little")
        if action in (0, 4):
            self.publish(device, "door_inferred", None, "unlock_pending", timestamp)
        elif action == 1 and method == 11:
            # Preserve an explicit closed contact, invalidate a contradictory open.
            raw = self.evidence.get("door", {}).get("state_source")
            if raw != "explicit_close":
                self.publish(device, "door", None, "unconfirmed_after_lock", timestamp)
            self.publish(device, "door_inferred", False, "automatic_lock", timestamp)
