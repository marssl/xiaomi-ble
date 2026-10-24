"""Synthetic D100 fixtures; no household addresses, keys or operator IDs."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import DeviceKey

from xiaomi_ble import EncryptionScheme, XiaomiBluetoothDeviceData
from xiaomi_ble.devices import DEVICE_TYPES

ADDRESS = "02:00:00:00:00:01"
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
SERVICE = "0000fe95-0000-1000-8000-00805f9b34fb"
NOW = 1_700_000_000


@pytest.fixture(autouse=True)
def current_time(monkeypatch):
    monkeypatch.setattr("xiaomi_ble.d100.time.time", lambda: NOW)


def advertisement(payload: bytes) -> BluetoothServiceInfo:
    return BluetoothServiceInfo(
        name="Synthetic D100",
        address=ADDRESS,
        rssi=-50,
        manufacturer_data={},
        service_data={SERVICE: payload},
        service_uuids=[SERVICE],
        source="synthetic-proxy",
    )


def encrypted_object(kind: int, value: bytes, counter: int = 1):
    mac = bytes.fromhex(ADDRESS.replace(":", ""))[::-1]
    header = bytes.fromhex("5855eb0b") + bytes([counter]) + mac
    extension = bytes([counter, 0, 0])
    nonce = mac + header[2:5] + extension
    objects = kind.to_bytes(2, "little") + bytes([len(value)]) + value
    encrypted = AESCCM(KEY, tag_length=4).encrypt(nonce, objects, b"\x11")
    return advertisement(header + encrypted[:-4] + extension + encrypted[-4:])


def test_d100_identity_stays_pending_without_fabricating_state():
    device = XiaomiBluetoothDeviceData()
    mac = bytes.fromhex(ADDRESS.replace(":", ""))[::-1]
    advert = advertisement(bytes.fromhex("1055eb0b01") + mac)
    assert device.supported(advert)
    assert DEVICE_TYPES[3051].model == "ZNMS20LM"
    assert DEVICE_TYPES[3051].manufacturer == "Aqara"
    assert device.pending
    assert device.encryption_scheme is EncryptionScheme.NONE
    assert not device.bindkey_verified
    update = device.update(advert)
    assert not update.binary_entity_values
    assert not update.events
    assert device.last_service_info is None


@pytest.mark.parametrize(("value", "opened"), [(0, True), (1, False)])
def test_d100_authenticated_door_objects(value, opened):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    advert = encrypted_object(
        0x0007, bytes([value]) + (1_700_000_000).to_bytes(4, "little")
    )
    assert device.supported(advert)
    assert device.bindkey_verified
    assert not device.pending
    update = device.update(advert)
    assert update.devices[None].model == "ZNMS20LM"
    assert update.devices[None].manufacturer == "Aqara"
    assert update.binary_entity_values[DeviceKey("door", None)].native_value is opened
    assert DeviceKey("lock", None) not in update.binary_entity_values


@pytest.mark.parametrize(("action", "unlocked"), [(0x20, True), (0xB1, False)])
def test_d100_lock_events_do_not_invent_door_state(action, unlocked):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    value = (
        bytes([action])
        + (0x80010001).to_bytes(4, "little")
        + (1_700_000_000).to_bytes(4, "little")
    )
    advert = encrypted_object(0x000B, value)
    assert device.supported(advert)
    assert device.bindkey_verified
    update = device.update(advert)
    assert update.binary_entity_values[DeviceKey("lock", None)].native_value is unlocked
    if action == 0xB1:
        assert update.binary_entity_values[DeviceKey("door", None)].native_value is None
        assert not update.binary_entity_values[
            DeviceKey("door_inferred", None)
        ].native_value
    else:
        assert DeviceKey("door", None) not in update.binary_entity_values
        assert (
            update.binary_entity_values[DeviceKey("door_inferred", None)].native_value
            is None
        )
    assert DeviceKey("lock", None) in update.events


def test_d100_battery_percentage_has_no_invented_voltage():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    advert = encrypted_object(0x100A, bytes([71]))
    assert device.supported(advert)
    update = device.update(advert)
    assert update.entity_values[DeviceKey("battery", None)].native_value == 71
    assert DeviceKey("voltage", None) not in update.entity_values


def test_d100_wrong_key_never_creates_door_state():
    device = XiaomiBluetoothDeviceData(
        bindkey=bytes.fromhex("ffeeddccbbaa99887766554433221100")
    )
    advert = encrypted_object(0x0007, b"\x01" + (1_700_000_000).to_bytes(4, "little"))
    assert device.supported(advert)
    update = device.update(advert)
    assert not device.bindkey_verified
    assert device.encryption_scheme is EncryptionScheme.MIBEACON_4_5
    assert not update.binary_entity_values
    assert not update.events


def door(code, timestamp=NOW):
    return bytes([code]) + timestamp.to_bytes(4, "little")


def lock(action, timestamp=NOW, operator=0x80010001):
    return (
        bytes([action])
        + operator.to_bytes(4, "little")
        + timestamp.to_bytes(4, "little")
    )


def state(update, key):
    return update.binary_entity_values[DeviceKey(key, None)].native_value


def test_d100_unlock_open_autolock_sequence_keeps_contact_separate():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    update = device.update(encrypted_object(0x000B, lock(0xB4, NOW - 7)))
    assert state(update, "door_inferred") is None
    update = device.update(encrypted_object(0x0007, door(0, NOW - 4), 2))
    assert state(update, "door") is True
    assert state(update, "door_inferred") is True
    update = device.update(encrypted_object(0x000B, lock(0xB1), 3))
    assert state(update, "lock") is False
    assert state(update, "door") is None
    assert state(update, "door_inferred") is False
    assert device.d100.evidence["door_inferred"] == {
        "state_source": "automatic_lock",
        "last_evidence_at": NOW,
        "inferred": True,
    }
    update = device.update(encrypted_object(0x0007, door(1, NOW + 1), 4))
    assert state(update, "door") is False
    assert state(update, "door_inferred") is False
    assert device.d100.evidence["door_inferred"]["inferred"] is False
    update = device.update(encrypted_object(0x000B, lock(0xB4, NOW + 2), 5))
    assert state(update, "door_inferred") is None


@pytest.mark.parametrize("code", [3, 4, 5])
def test_d100_knock_pry_and_stuck_do_not_change_position(code):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    device.update(encrypted_object(0x0007, door(0, NOW - 1)))
    update = device.update(encrypted_object(0x0007, door(code), 2))
    assert state(update, "door") is True
    assert state(update, "door_inferred") is True
    assert device.d100.evidence["door"]["last_evidence_at"] == NOW - 1


@pytest.mark.parametrize("action", [0xB2, 0xB3, 0xB6, 0xB7, 0xB5, 0xB8, 0xFF])
def test_d100_secondary_and_nonautomatic_actions_do_not_infer_closed(action):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    device.update(encrypted_object(0x0007, door(0, NOW - 1)))
    update = device.update(encrypted_object(0x000B, lock(action), 2))
    assert state(update, "door") is True
    assert state(update, "door_inferred") is True
    if action & 0x0F in (2, 3, 6, 7, 15):
        assert DeviceKey("lock", None) not in update.binary_entity_values


@pytest.mark.parametrize("timestamp", [NOW - 121, NOW + 31, 0])
@pytest.mark.parametrize(
    "kind,value", [(0x0007, lambda t: door(1, t)), (0x000B, lambda t: lock(0xB1, t))]
)
def test_d100_stale_or_future_events_do_not_create_states(kind, value, timestamp):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    update = device.update(encrypted_object(kind, value(timestamp)))
    assert device.bindkey_verified
    assert not update.binary_entity_values
    assert not update.events
    assert not device.d100.evidence


@pytest.mark.parametrize(
    "kind,value",
    [
        (0x0007, b""),
        (0x0007, b"\x01"),
        (0x0007, door(1) + b"\x00"),
        (0x000B, lock(0xB1)[:-1]),
    ],
)
def test_d100_malformed_events_do_not_create_states(kind, value):
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    update = device.update(encrypted_object(kind, value))
    assert not update.binary_entity_values
    assert not update.events


def test_d100_repeats_and_out_of_order_events_do_not_rollback():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    advert = encrypted_object(0x000B, lock(0xB1))
    device.update(advert)
    update = device.update(advert)
    assert not update.events
    update = device.update(encrypted_object(0x0007, door(0, NOW - 1), 2))
    assert state(update, "door_inferred") is False
    assert state(update, "door") is None
    assert device.d100.evidence["door_inferred"]["last_evidence_at"] == NOW


def test_d100_error_reports_only_alarm():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    update = device.update(encrypted_object(0x000B, lock(0xB1, operator=0xC0DE1004)))
    assert DeviceKey("error", None) in update.events
    assert DeviceKey("lock", None) not in update.events
    assert not update.binary_entity_values
    assert not device.d100.evidence
    assert DeviceKey("key_id", None) not in update.entity_values


def test_d100_requires_current_packet_authentication_after_valid_packet():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    device.update(encrypted_object(0x0007, door(0, NOW - 1)))
    mac = bytes.fromhex(ADDRESS.replace(":", ""))[::-1]
    plain = bytes.fromhex("5055eb0b02") + mac + bytes.fromhex("070005") + door(1)
    update = device.update(advertisement(plain))
    assert state(update, "door") is True
    assert device.d100.evidence["door"]["last_evidence_at"] == NOW - 1
    wrong = XiaomiBluetoothDeviceData(bindkey=bytes(16))
    payload = encrypted_object(0x0007, door(1), 3)
    # The sticky verified flag from the previous packet cannot authenticate this one.
    wrong.bindkey_verified = True
    update = wrong.update(payload)
    assert not update.binary_entity_values


def test_d100_discovery_does_not_consume_event_or_restore_old_contact():
    advert = encrypted_object(0x0007, door(1))
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    assert device.supported(advert)
    assert not device.d100.evidence
    assert state(device.update(advert), "door") is False
    restarted = XiaomiBluetoothDeviceData(bindkey=KEY)
    assert not restarted.d100.evidence
    update = restarted.update(encrypted_object(0x0007, door(1, NOW - 600), 2))
    assert not update.binary_entity_values


def test_d100_explicit_close_survives_normal_auto_lock():
    device = XiaomiBluetoothDeviceData(bindkey=KEY)
    device.update(encrypted_object(0x0007, door(1, NOW - 1)))
    update = device.update(encrypted_object(0x000B, lock(0xB1), 2))
    assert state(update, "door") is False
    assert device.d100.evidence["door"]["state_source"] == "explicit_close"
