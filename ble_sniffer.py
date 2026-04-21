#!/usr/bin/env python3
"""
BLE LampSmart Pro packet sniffer and decoder.
Captures advertisements from all devices and decodes known LampSmart/FanLamp formats.

Usage:
    python3 ble_sniffer.py

Press Ctrl+C to stop.
"""

import asyncio
import struct
from datetime import datetime
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

PHONE_HINT = "48:5F:99:16:62:1C".upper()  # hint only - macOS may show random MACs

# Only show packets from these company IDs (set empty to show all non-Apple)
FILTER_COMPANY_IDS: set = set()  # empty = show all non-Apple

# Ignore these known-noisy devices by name fragment
IGNORE_NAMES = {"DV2_", "LG] webOS", "Fridge", "Living room tv", "BL-35788"}

# Ignore these stable company IDs we've confirmed are not the light
IGNORE_COMPANY_IDS = {0x2502, 0x0075, 0x00C4, 0x00E0, 0x582B}

# Known company IDs for LampSmart ecosystem
KNOWN_COMPANY_IDS = {
    0x012D: "LampSmart Pro (new) - PHONE",
    0x0210: "FanLamp/LampSmart (old)",
    0x5677: "LIGHT STATE BROADCAST",
}

# Known BLE AD types used by this ecosystem
LAMPSMART_SERVICE_UUID_16 = 0x0810  # UUID bytes F0 08 reversed

CMD_NAMES = {
    0x28: "PAIR",
    0x45: "UNPAIR",
    0x10: "LIGHT_ON",
    0x11: "LIGHT_OFF",
    0x21: "LIGHT_WCOLOR",
    0x12: "LIGHT_SEC_ON",
    0x13: "LIGHT_SEC_OFF",
    0x31: "FAN_ONOFF_SPEED",
    0x15: "FAN_DIR",
    0x16: "FAN_OSC",
}

seen_packets: set[str] = set()


def fmt_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def decode_lampsmart_v2_v3(payload: bytes, variant: str) -> dict | None:
    """
    Try to decode FanLampEncoderV2 packet (lampsmart_pro v2/v3, fanlamp_pro v3).
    Prefix for v2: 10 80 00, for v3: 30 80 00
    Full header in advertisement (after service UUID bytes F0 08): prefix[0..2]
    """
    # payload here is the raw data bytes after the AD type and UUID
    if len(payload) < 16:
        return None

    prefix_v2 = bytes([0x10, 0x80])
    prefix_v3 = bytes([0x30, 0x80])

    if payload[:2] == prefix_v2:
        var = "v2"
    elif payload[:2] == prefix_v3:
        var = "v3"
    else:
        return None

    # data_map_t layout (from FanLampEncoderV2):
    # The payload is encrypted/whitened so we can't easily decode without the key,
    # but we can show the raw bytes and tx_count
    return {
        "variant": var,
        "raw_payload": payload,
    }


def decode_manufacturer_packet(company_id: int, data: bytes) -> dict:
    result = {
        "company_id": f"0x{company_id:04X}",
        "company_name": KNOWN_COMPANY_IDS.get(company_id, "Unknown"),
        "raw_data": fmt_hex(data),
        "length": len(data),
    }

    if company_id == 0x012D and len(data) >= 4:
        # New LampSmart Pro format seen from phone
        # Byte structure: 02 00 01 10 [12 bytes encrypted] ...
        result["prefix"] = fmt_hex(data[:4])
        result["encrypted_payload"] = fmt_hex(data[4:])
        result["note"] = "New LampSmart Pro protocol (not yet implemented in ESPHome component)"

        # The forced_id / controller ID may be embedded — need multiple packets to reverse-engineer
        result["hint"] = "Capture 5+ packets while operating the light for pattern analysis"

    return result


def decode_service_data_packet(uuid16: int, data: bytes) -> dict | None:
    """Decode service data AD type (0x16) with 16-bit UUID."""
    result = {
        "uuid16": f"0x{uuid16:04X}",
        "raw_data": fmt_hex(data),
    }
    return result


def analyze_advertisement(device: BLEDevice, adv: AdvertisementData):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    output_lines = []

    # --- Manufacturer Specific Data (AD type 0xFF) ---
    for company_id, mfr_data in adv.manufacturer_data.items():
        # Skip Apple and explicitly ignored company IDs
        if company_id == 0x004C:
            continue
        if company_id in IGNORE_COMPANY_IDS:
            continue
        if FILTER_COMPANY_IDS and company_id not in FILTER_COMPANY_IDS:
            continue
        if any(n in (device.name or "") for n in IGNORE_NAMES):
            continue

        packet_key = f"mfr-{company_id}-{mfr_data.hex()}"
        if packet_key in seen_packets:
            continue  # suppress repeats entirely
        seen_packets.add(packet_key)

        decoded = decode_manufacturer_packet(company_id, mfr_data)

        output_lines.append(f"\n{'='*60}")
        output_lines.append(f"[{timestamp}] NEW Manufacturer Specific Advertisement")
        output_lines.append(f"  Device:      {device.address}  RSSI: {adv.rssi} dBm")
        if device.name:
            output_lines.append(f"  Name:        {device.name}")
        output_lines.append(f"  Company ID:  {decoded['company_id']} ({decoded['company_name']})")
        output_lines.append(f"  Raw data:    {decoded['raw_data']}")
        if "prefix" in decoded:
            output_lines.append(f"  Prefix:      {decoded['prefix']}")
            output_lines.append(f"  Payload:     {decoded['encrypted_payload']}")
        if "note" in decoded:
            output_lines.append(f"  NOTE:        {decoded['note']}")
        if "hint" in decoded:
            output_lines.append(f"  HINT:        {decoded['hint']}")

        # Full raw hex for copy-paste
        full_raw = struct.pack("<H", company_id) + mfr_data
        output_lines.append(f"  Full hex:    0xFF {fmt_hex(full_raw)}")

    # --- Service Data (AD type 0x16) - used by older lampsmart_pro ---
    for uuid_str, svc_data in adv.service_data.items():
        # Filter for 16-bit UUIDs in LampSmart range
        try:
            # bleak returns UUIDs as "0000XXXX-0000-1000-8000-00805f9b34fb"
            uuid16 = int(uuid_str.split("-")[0], 16) & 0xFFFF
        except Exception:
            continue

        if uuid16 not in (0x0810, 0x0310, 0xFFF0, 0xFFF1):
            continue

        packet_key = f"svc-{uuid16}-{svc_data.hex()}"
        if packet_key in seen_packets:
            continue  # suppress repeats
        seen_packets.add(packet_key)

        output_lines.append(f"\n{'='*60}")
        output_lines.append(f"[{timestamp}] NEW Service Data Advertisement (LampSmart)")
        output_lines.append(f"  Device:      {device.address}  RSSI: {adv.rssi} dBm")
        output_lines.append(f"  UUID16:      0x{uuid16:04X}")
        output_lines.append(f"  Data:        {fmt_hex(svc_data)}")

    if output_lines:
        # Also show service UUIDs if present (hints at GATT profile)
        if adv.service_uuids:
            output_lines.append(f"  Service UUIDs: {adv.service_uuids}")
        print("\n".join(output_lines))


def callback(device: BLEDevice, adv: AdvertisementData):
    analyze_advertisement(device, adv)


async def main():
    print("BLE LampSmart Pro Sniffer")
    print("=" * 60)
    print(f"Phone MAC hint: {PHONE_HINT}")
    print("NOTE: macOS may show randomized MACs instead of real ones.")
    print("Scanning for ALL non-Apple manufacturer-specific advertisements")
    print("and service data matching LampSmart UUIDs.")
    print("\nOpen LampSmart Pro and operate your light (on/off/dim/pair).")
    print("Press Ctrl+C to stop.\n")

    scanner = BleakScanner(detection_callback=callback)
    await scanner.start()

    try:
        i = 0
        while True:
            await asyncio.sleep(1)
            i += 1
            print(f"\r[scanning... {i}s, {len(seen_packets)} unique LampSmart packets captured]", end="", flush=True)
    except KeyboardInterrupt:
        print("\n\nStopping scanner...")
    finally:
        await scanner.stop()
        print(f"\nCaptured {len(seen_packets)} unique packets.")


if __name__ == "__main__":
    asyncio.run(main())
