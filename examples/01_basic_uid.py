"""
Example 01 — Basic card UID polling
====================================
Connects to the reader, demonstrates `get_uid()`, `get_uid_int()`, and `scan_tag()`.

Usage:
    python 01_basic_uid.py [port]          (port default: /dev/ttyUSB0)
"""

import sys
from mifarepy import MifareReader, CardInfo

PORT = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'

with MifareReader(port=PORT) as reader:
    print(f'Connected — {repr(reader)}')
    print(f'Firmware: {reader.get_version()}')
    print(f'Ping: {reader.ping()}')

    print('\nPlace a card on the reader, then press Enter...')
    input()

    # Quick UID without selecting the card
    uid_str = reader.get_uid()
    uid_int = reader.get_uid_int()
    print(f'  UID string:  {uid_str}')
    print(f'  UID integer: {uid_int}')

    # scan_tag: REQUEST+ANTI_COLLISION+SELECT in one call, returns CardInfo
    card: CardInfo = reader.scan_tag()
    print(f'  CardInfo:    {card}           ({repr(card)})')
    print(f'  uid_bytes:   {card.uid_bytes.hex()}')
