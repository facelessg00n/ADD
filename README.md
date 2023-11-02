# ADD
Apple Device Detector

Detects the presense of Apple devices and identifies nearby Airtags.

Apple devices emit BLE beacons to indicate their prescense to other nearby Apple so they can perform actions such as Airdrop and Handoff. Apple Airtags and other devices on the FindMy network also emit BLE beacons which can be detected. FindMy network beacons are a fixed legnth and AirTags can be identified by the status bytes which are also transmitted.

Usage
Dependencies

Pandas -Bleak
The script can be run with default options by running it without any options added python3 appleDeviceDetector.py however further fine tuning options are available and are listed below.

The help guide can also be displayed by running python3 appleDeviceDetector.py -h

usage: appleDeviceDetector.py [-h] [-t TIMEOUT] [-s {RSSI,LAST_SEEN}] [-a BLUETOOTHADAPTER]

Detects and displays a list of BLE devices emitting Apple Find my Beacons or Continuity packets

options:

-h, --help show this help message and exit

-t TIMEOUT, --timeout TIMEOUT Time in seconds before items are removed from list. Defaults to 120 Seconds

-s {RSSI,LAST_SEEN}, --sort {RSSI,LAST_SEEN} Select to sort by time last seen or RSSI (signal strength)

-a BLUETOOTHADAPTER, --adapter BLUETOOTHADAPTER To use an alternative bluetooth adapter enter details here, i.e hci1

Detects the presense of Apple devices and identifies nearby Airtags.

Apple devices emit BLE beacons to indicate their prescense to other nearby Apple so they can perform actions such as Airdrop and Handoff. Apple Airtags and other devices on the FindMy network also emit BLE beacons which can be detected. FindMy network beacons are a fixed legnth and AirTags can be identified by the status bytes which are also transmitted.

Usage
Dependencies

- Pandas 
- Bleak

The script can be run with default options by running it without any options added python3 appleDeviceDetector.py however further fine tuning options are available and are listed below.

The help guide can also be displayed by running python3 appleDeviceDetector.py -h

usage: appleDeviceDetector.py [-h] [-t TIMEOUT] [-s {RSSI,LAST_SEEN}] [-a BLUETOOTHADAPTER]

Detects and displays a list of BLE devices emitting Apple Find my Beacons or Continuity packets

options:

-h, --help show this help message and exit

-t TIMEOUT, --timeout TIMEOUT Time in seconds before items are removed from list. Defaults to 120 Seconds

-s {RSSI,LAST_SEEN}, --sort {RSSI,LAST_SEEN} Select to sort by time last seen or RSSI (signal strength)

-a BLUETOOTHADAPTER, --adapter BLUETOOTHADAPTER To use an alternative bluetooth adapter enter details here, i.e hci1

└─$ /bin/python /home/kali/scapyPython/appleDeviceDetector.py -h     


usage: appleDeviceDetector.py [-h] [-t TIMEOUT] [-s {RSSI,LAST_SEEN}] [-a BLUETOOTHADAPTER] [-n {1}] [-m TARGETMAC]

Detects and displays a list of BLE devices emitting Apple Find my packets or Apple continuity packets

options:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
                        Time in seconds before items are removed from list. Defaults to 120 Seconds
  -s {RSSI,LAST_SEEN}, --sort {RSSI,LAST_SEEN}
                        Select to sort by time last seen or RSSI (signal strength)
  -a BLUETOOTHADAPTER, --adapter BLUETOOTHADAPTER
                        To use an alternative bluetooth adapter enter details here, i.e hci1
  -n {1}, --noise {1}   To force discovered airtags to play their alert tones. Airtag must not have been in contact with its owner for 15 minutes.
  -m TARGETMAC, --mac TARGETMAC
                        Specify an airtag to force to play its alert tone. Airtag must not have been in contact with its owner for 15 minutes.


                                                
