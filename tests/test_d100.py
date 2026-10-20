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
    assert DeviceKey("door", None) not in update.binary_entity_values
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
