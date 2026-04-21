#!/usr/bin/env python3
"""
Connect to the light (0x5677 advertiser) and dump all GATT services/characteristics.
Run AFTER power-cycling the light (so it's in a known state).
"""
import asyncio
from bleak import BleakScanner, BleakClient

LIGHT_COMPANY_ID = 0x5677
SCAN_TIMEOUT = 15  # seconds to scan for the light


async def find_light() -> str | None:
    print(f"Scanning for light (company ID 0x{LIGHT_COMPANY_ID:04X})...")
    found_addr = None

    def callback(device, adv):
        nonlocal found_addr
        if LIGHT_COMPANY_ID in adv.manufacturer_data and found_addr is None:
            found_addr = device.address
            print(f"  Found light: {device.address}  RSSI: {adv.rssi} dBm")

    scanner = BleakScanner(detection_callback=callback)
    await scanner.start()
    for _ in range(SCAN_TIMEOUT * 2):
        await asyncio.sleep(0.5)
        if found_addr:
            break
    await scanner.stop()
    return found_addr


async def explore_gatt(address: str):
    print(f"\nConnecting to {address}...")
    async with BleakClient(address, timeout=20.0) as client:
        print(f"Connected: {client.is_connected}")
        print(f"MTU: {client.mtu_size}")
        print()

        notifications = []

        def notification_handler(char, data: bytearray):
            hex_str = " ".join(f"{b:02X}" for b in data)
            print(f"  [NOTIFY] {char.uuid}: {hex_str}")
            notifications.append((str(char.uuid), bytes(data)))

        print("=" * 60)
        print("GATT Services and Characteristics")
        print("=" * 60)

        for service in client.services:
            print(f"\nService: {service.uuid}")
            if service.description:
                print(f"  Description: {service.description}")

            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"\n  Char: {char.uuid}")
                print(f"    Properties: {props}")
                if char.description:
                    print(f"    Description: {char.description}")

                # Try to read readable characteristics
                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char.uuid)
                        hex_str = " ".join(f"{b:02X}" for b in val)
                        print(f"    Current value: {hex_str}")
                    except Exception as e:
                        print(f"    Read failed: {e}")

                # Subscribe to notifications
                if "notify" in char.properties or "indicate" in char.properties:
                    try:
                        await client.start_notify(char.uuid, notification_handler)
                        print(f"    Subscribed to notifications")
                    except Exception as e:
                        print(f"    Subscribe failed: {e}")

        print("\n" + "=" * 60)
        print("Listening for notifications for 15 seconds...")
        print("Operate the light with the phone app during this time.")
        print("=" * 60)
        await asyncio.sleep(15)

        if notifications:
            print(f"\nCaptured {len(notifications)} notifications:")
            for uuid, data in notifications:
                hex_str = " ".join(f"{b:02X}" for b in data)
                print(f"  {uuid}: {hex_str}")
        else:
            print("\nNo notifications received.")


async def main():
    address = await find_light()
    if not address:
        print(f"Light not found after {SCAN_TIMEOUT}s. Make sure it's powered on.")
        return
    await explore_gatt(address)


if __name__ == "__main__":
    asyncio.run(main())
