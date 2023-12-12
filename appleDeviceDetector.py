# Detects the presence of Airtags and other Apple devices
# Apple devices emit BLE data which can reveal their presence and type

## Changelog
# 0.4 - Support for Low and Critical battery state Airtags
#     - Were not previously flagged as possible Airtags due to status bytes not being confirmed
#     - Some spelling corrections
# 0.3 - MAC Address input validation for sound requests
# 0.2 - Error handling added if bluetooth service is not started or adapter is down
#       Added ability to cause an Airtag to play its alert tone
#       Added lookup to show textual representation of activity types and tested common types
#           Idle, Screen on and off etc
# 0.1 - Initial Concept

import sys

PY3 = sys.version_info[0] == 3
if not PY3:
    print("Run with Python 3")
    sys.exit()

import argparse
import asyncio
import binascii
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from construct import Array, Byte, Const, Int8sl, Struct, Int8ub, Int8ul
from construct.core import ConstError
from datetime import datetime, timedelta
import pandas as pd
import os
import re
import sys
import subprocess as sp

###--------------- Setup items ---------------------------------------------------------------

# Enable debug prints
DEBUG = False

__description__ = "Detects and displays a list of BLE devices emitting Apple Find my packets or Apple continuity packets"
__author__ = "facelessg00n"
__version__ = "0.4"

# Endpoints for Airtag sound requests
SERVICE_UUID = "7dfc9000-7d1c-4951-86aa-8d9728f8d66c"
# Service endpoint for unauthenticated device to set off the alarm
SOUND_UUID = "7dfc9001-7d1c-4951-86aa-8d9728f8d66c"
# Send this message to the above UDID to set off the alert tone.
MSG_BYTES = bytearray([0xAF])

# Regex to validate MAC addresses
mac_match = re.compile("^(([0-9|A-F|a-f]{2}:){5}[0-9|A-F|a-f]{2})")

banner = """
_______                ______          ________            _____            
___    |__________________  /____      ___  __ \_______   ____(_)__________ 
__  /| |__  __ \__  __ \_  /_  _ \     __  / / /  _ \_ | / /_  /_  ___/  _ \\
_  ___ |_  /_/ /_  /_/ /  / /  __/     _  /_/ //  __/_ |/ /_  / / /__ /  __/
/_/  |_|  .___/_  .___//_/  \___/      /_____/ \___/_____/ /_/  \___/ \___/ 
       /_/     /_/                                                          
________     _____           _____              
___  __ \______  /_____________  /______________
__  / / /  _ \  __/  _ \  ___/  __/  __ \_  ___/
_  /_/ //  __/ /_ /  __/ /__ / /_ / /_/ /  /    
/_____/ \___/\__/ \___/\___/ \__/ \____//_/                                                   
"""


# -------------Parsers -----------------------------------------

# Confirmed Activity Types

AppleActivityTypes = {
    0x05: "Airdrop",
    0x07: "Proximity Pairing",
    0x10: "Nearby Info",
    0x12: "Find My",
    0x0C: "Handoff",
}

airTagChargeState = {
    0x10: "Airtag - Fully Charged",
    0x50: "Airtag - Medium Charge",
    0x90: "Airtag - Low battery",
    0xD0: "Airtag - Critical battery",
}

# Struct to parse Apple Find My Network data
# Of note other devices such as Airpods can also use this network
#
#                                     Remaining Mac - 2 Bits
#                                             |^|
# 00 FF 4C00 00 00 00 0000000000000000000000 00 00
# |  |  |    |  |  |  |                    |   |
# |  |  |    |  |  |  |                    |   \_Hint
# |  |  |    |  |  |   \_22 Bytes_________/
# |  |  |    |  |  |
# |  |  |    |  |  \ Status - Encodes Device Type and battery level - 0x10 Charged Airtag
# |  |  |    |  |             0x50 Medium Battery Airtag
# |  |  |    |   \ Data Length
# |  |  |     \ Offline Finding Type - 0x12 (Find My) 0x07 (Unpaired or other)
# |  |   \ Company ID 0x004C - 76
# |   \_ADV Type - FF = Manufacturer data
#  \_Payload Length

# TODO - Need to confirm Endinaness
findmy_format = Struct(
    "OF_TYPE" / Int8ul,
    "DATA_LEN" / Int8ul,
    "STATUS" / Int8ul,
    "DATA" / Array(22, Byte),
    "ITEM1" / Int8ul,
    "HINT" / Int8ul,
)

# Struct to parse Apple Continuity packets
# 00 FF 4C00 10 00 00 0000000000000000000000
# |  |  |    |  |  |  |                    |
# |  |  |    |  |  |   \__Data____________/
# |  |  |    |  |
# |  |  |    |   \ Data Length
# |  |  |     \ Type
# |  |   \ Company ID 0x004C - 76
# |   \_ADV Type - FF = Manufacturer data
#  \_Payload Length

# TODO - Need to confirm Endinaness
# TODO - Activity type may be multiple bytes?

continuity_format = Struct(
    "TYPE" / Int8ul,
    "DATA_LENGTH" / Int8ul,
    "ACTIVITY_TYPE" / Int8ul,
    "INFORMATION" / Int8ul,
)
# - Activity levels inspired by the NetSpooky Wireshark Dissectors
# - Some activity types to be confirmed

NearbyInfoActivityLevels = {
    0x00: "Activity level is not known",
    0x01: "Activity reporting is disabled",
    0x33: "Device is idle",
    # 0x05: "Audio is playing with the screen off",
    0x13: "Screen off",
    0x57: "Screen on",
    0x77: "Screen is on",
    0x09: "Screen on and video playing",
    # 0x0A: "Watch is on wrist and unlocked",
    0x7B: "Recent user interaction",
    # 0x0D: "User is driving a vehicle",
    0x5E: "Phone call or Facetime",
}

# -------------- Data Frames to hold items for display---------------------------------

findMy_devices = pd.DataFrame(
    columns=[
        "MAC",
        "TYPE",
        "STATUS",
        "LENGTH",
        "RSSI",
        "LIKELY_AIRTAG",
        "LAST_SEEN",
        "LAST_SEEN_CALC",
    ]
)
findMy_devices.set_index("MAC", inplace=True)

apple_devices = pd.DataFrame(
    columns=[
        "MAC",
        "TYPE",
        "ACTIVITY_TYPE",
        "DATA_LENGTH",
        "RSSI",
        "LAST_SEEN",
        "LAST_SEEN_CALC",
    ]
)
apple_devices.set_index("MAC", inplace=True)


# ----------- Callback function for found devices-----------------------
def device_found(device: BLEDevice, advertisement_data: AdvertisementData):
    global apple_data
    global NearbyInfoActivityLevels
    global AppleActivityTypes
    """Decode."""
    try:
        if advertisement_data.manufacturer_data[0x004C]:
            if DEBUG:
                print("Found an Apple Device By manufacturer code 76")
                print(
                    f"Length of packet is : {len(advertisement_data.manufacturer_data[0x004C])}"
                )

            # Airtags and Findmy network devices emit fixed length packets
            if len((advertisement_data.manufacturer_data[0x004C])) == 27:
                try:
                    apple_data = advertisement_data.manufacturer_data[0x004C]
                    # Parse packets using struct
                    findMY = findmy_format.parse(apple_data)
                    findMyType = hex(findMY.OF_TYPE)
                    findMyStatus = hex(findMY.STATUS)
                    if DEBUG:
                        print(findMyType)
                        print(f"OF_TYPE    : {hex(findMY.OF_TYPE)}")
                        print(f"DATA_LEN   : {hex(findMY.DATA_LEN)}")
                        print(f"STATUS     : {hex(findMY.STATUS)}")
                        print(
                            f"DATA       : {binascii.hexlify(bytearray(findMY.DATA))}"
                        )
                        print(f"RSSI       : {advertisement_data.rssi} dBm")
                        print(advertisement_data.tx_power)
                        print(advertisement_data.platform_data[1]["Address"])

                    # Airtag Find My status is 0x10 - Fully charged, 0x50 medium charge.
                    # 0x90 and 0xD0 for Low and Critical battery states. 0XD0 is confirmed and 0x90 is assumed due to documentation
                    if (
                        findMyStatus == "0x10"
                        or findMyStatus == "0x50"
                        or findMyStatus == "0x90"
                        or findMyStatus == "0xD0"
                    ):
                        likelyTAG = "YES"
                    else:
                        likelyTAG = "NO"
                    dev_mac = advertisement_data.platform_data[1]["Address"]

                    # Add item to dataframe, indexed on MAC address
                    findMy_devices.loc[dev_mac] = (
                        hex(findMY.OF_TYPE),
                        hex(findMY.STATUS),
                        findMY.DATA_LEN,
                        advertisement_data.rssi,
                        likelyTAG,
                        datetime.now().strftime("%H:%M:%S"),
                        datetime.now(),
                    )

                except Exception as e:
                    print(e)

            # Detect and deal with Apple continuity packets
            elif (
                len((advertisement_data.manufacturer_data[0x004C])) >= 4
                and len((advertisement_data.manufacturer_data[0x004C])) <= 25
            ):
                if DEBUG:
                    print("Continuity Protocol Detected")
                try:
                    apple_data = advertisement_data.manufacturer_data[0x004C]
                    continuityProtocol = continuity_format.parse(apple_data)

                    if DEBUG:
                        print(advertisement_data.platform_data[1]["Address"])
                        print(f"Continuity_TYPE    : {hex(continuityProtocol.TYPE)}")
                        print(
                            f"Continuity Length   : {hex(continuityProtocol.DATA_LEN)}"
                        )
                        print(
                            f"Activity Type     : {hex(continuityProtocol.ACTIVITY_TYPE)}"
                        )
                        print(f"RSSI     : {advertisement_data.rssi} dBm")
                        print(advertisement_data.tx_power)
                        print(advertisement_data.platform_data[1]["Address"])
                        print(advertisement_data.platform_data)

                    # Process activity types
                    dev_mac = advertisement_data.platform_data[1]["Address"]
                    actType = continuityProtocol.ACTIVITY_TYPE
                    contType = continuityProtocol.TYPE

                    if actType in NearbyInfoActivityLevels:
                        text_rep = NearbyInfoActivityLevels.get(actType, actType)
                        actType = text_rep
                    else:
                        actType = hex(continuityProtocol.ACTIVITY_TYPE)

                    if contType in AppleActivityTypes:
                        apple_type = AppleActivityTypes.get(contType)
                        contType = apple_type
                    else:
                        contType = hex(continuityProtocol.TYPE)

                    # Push data into dataframe
                    apple_devices.loc[dev_mac] = (
                        contType,
                        # hex(continuityProtocol.TYPE),
                        actType,
                        # hex(continuityProtocol.ACTIVITY_TYPE),
                        continuityProtocol.DATA_LENGTH,
                        advertisement_data.rssi,
                        datetime.now().strftime("%H:%M:%S"),
                        datetime.now(),
                    )

                except Exception as e:
                    print(e)
            else:
                print("Unhandled continuity length")
                pass

        else:
            print("Other manufacturer")
            pass

    # TODO - Tidy up error handling
    # Apple company ID (0x004c) not found
    except KeyError:
        # print("Key error")
        pass

    except ConstError:
        print("Const Error")
        pass

    except Exception as e:
        print(e)


# Cleans dataframe by removing items that have not been seen for a set period of seconds
# Set to a default of 120 seconds in Argparse
async def clean_data(timeout_seconds_in):
    global apple_devices
    global findMy_devices
    # global airTags
    timeout_seconds = timeout_seconds_in

    while True:
        time_threshold = datetime.now() - timedelta(seconds=timeout_seconds)
        if apple_devices.empty:
            pass
        else:
            try:
                print("Cleaning dataframe")
                apple_devices = apple_devices[
                    apple_devices["LAST_SEEN_CALC"] >= time_threshold
                ]
                pass
            except Exception as e:
                print(e)
                pass

        if findMy_devices.empty:
            pass

        else:
            try:
                findMy_devices = findMy_devices[
                    findMy_devices["LAST_SEEN_CALC"] >= time_threshold
                ]

            except Exception as e:
                print(e)
                pass
        await asyncio.sleep(5)


airTagMacList = []


# ----------------------- Display Loop -------------------------------------------
# Displays found devices
async def display_loop(sortType, timeout_seconds, bluetoothAdapter):
    global apple_devices
    global findMy_devices
    global airTagMacList

    while True:
        if not DEBUG:
            os.system("clear")
            print(banner)
            print(
                "Version - {}. Using {}, sorting by {}, timeout set to {} seconds\n".format(
                    str(__version__),
                    str(bluetoothAdapter),
                    str(sortType),
                    str(timeout_seconds),
                )
            )
            print(
                f"Current Time                                               {datetime.now().strftime('%H:%M:%S')}\n"
            )
            print(f"Find My Network Devices - {len(findMy_devices)}")
            print(75 * "_")
            if findMy_devices.empty:
                print("Nil Detected")
            else:
                print(
                    findMy_devices[
                        [
                            "TYPE",
                            "STATUS",
                            "LENGTH",
                            "RSSI",
                            "LIKELY_AIRTAG",
                            "LAST_SEEN",
                        ]
                    ].sort_values(by=[sortType], ascending=False)
                )

            print(f"\nOther Apple Devices      - {len(apple_devices)}")
            print(75 * "_")
            if apple_devices.empty:
                print("Nil Detected")
            else:
                print(
                    apple_devices[
                        ["TYPE", "ACTIVITY_TYPE", "DATA_LENGTH", "RSSI", "LAST_SEEN"]
                    ]
                    .sort_values(by=[sortType], ascending=False)
                    .head(25)
                )
            try:
                airTagMacList = findMy_devices.index[
                    findMy_devices["LIKELY_AIRTAG"] == "YES"
                ].tolist()
            except:
                airTagMacList = []
                pass
            if DEBUG:
                print(airTagMacList)

        await asyncio.sleep(1)


# Scans for BLE devices and calls the callback function "device_found"
async def scan_loop(bluetoothAdapter):
    scanner = BleakScanner(device_found, adapter=bluetoothAdapter)
    while True:
        try:
            await scanner.start()

        # FIXME Ensure this correctly handles hci0 being down
        except Exception as e:
            print(e)
            quit()

        await asyncio.sleep(1.0)
        await scanner.stop()


# Constantly connect and send 'play sound' bytes
# This will always fail on a first attempt as an Airtag requires a previous connection attempt.
async def sound_loop(targetMAC):
    if bool(mac_match.match(targetMAC)):
        print(f"Targeting device: {str(targetMAC)}")
        while True:
            try:
                client = BleakClient(targetMAC)
                await client.connect()
                await client.write_gatt_char(SOUND_UUID, MSG_BYTES)
                # await asyncio.sleep(1.0)
            except Exception as e:
                print(
                    "Failed Device needs to be away from its owner for 15 minutes for this to work - Retrying"
                )
                print(e)
    else:
        print(
            f"TARGET MAC:{targetMAC} is invalid, please use the format of aa:bb:cc:dd:ee:ff"
        )


# --------------- Bluetooth Scan loop ----------------------------------------------------------


def bluetooth_scan(sortType, timeout_seconds, bluetoothAdapter):
    loop = asyncio.get_event_loop()

    # Janky way of checking if there is a bluetooth adapter present
    hciCheck = sp.getoutput("hcitool dev")

    if "hci0" in hciCheck.split():
        print("\nBluetooth device is present")
    else:
        print("\n\nBluetooth device not detected, try running 'sudo hciconfig hci0 up'")
        quit()

    # Check to see if Bluetooth service is active
    bluetoothServiceStatus = sp.getoutput("service bluetooth status").split("\n")[2]
    if "inactive" in bluetoothServiceStatus:
        print("Bluetooth Disabled")
        print(
            "Bringing service online, you will need to enter your SUDO password or run the command sudo service bluetooth start'"
        )
        sp.getoutput("service bluetooth start")
    else:
        print("Bluetooth service present")
        pass

    try:
        asyncio.ensure_future(scan_loop(bluetoothAdapter))
        asyncio.ensure_future(clean_data(timeout_seconds))
        asyncio.ensure_future(display_loop(sortType, timeout_seconds, bluetoothAdapter))

        loop.run_forever()

    except KeyboardInterrupt:
        loop.close()
        quit()

    finally:
        print("Closing loop")
        loop.close()


# ----------- Argument Parser ----------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {}, version {}".format(str(__author__), str(__version__)),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        dest="timeout",
        default=120,
        required=False,
        help="Time in seconds before items are removed from list. Defaults to 120 Seconds",
    )

    parser.add_argument(
        "-s",
        "--sort",
        dest="sortType",
        default="RSSI",
        required=False,
        choices=["RSSI", "LAST_SEEN"],
        help="Select to sort by time last seen or RSSI (signal strength)",
    )

    parser.add_argument(
        "-a",
        "--adapter",
        dest="bluetoothAdapter",
        default="hci0",
        required=False,
        help="To use an alternative bluetooth adapter enter details here, i.e hci1",
    )

    parser.add_argument(
        "-m",
        "--mac",
        dest="targetMAC",
        required=False,
        help="Specify an Airtag to force to repeatedly play its alert tone. Airtag must not have been in contact with its owner for 15 minutes.",
    )

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit

    if args.targetMAC is not None:
        print("Airtag alert tone request sent. Will always fail on first attempt.")
        asyncio.run(sound_loop(args.targetMAC))
    else:
        bluetooth_scan(args.sortType, int(args.timeout), args.bluetoothAdapter)
