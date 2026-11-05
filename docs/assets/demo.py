"""Demo used to record docs/assets/demo.gif (re-record with record.sh).

Usage:
    python docs/assets/demo.py [port]
"""

import sys

from mifarepy import MifareReader

PORT = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
DEFAULT_KEY = bytes.fromhex('FFFFFFFFFFFF')

with MifareReader(PORT) as reader:
    print(f'Reader firmware: {reader.get_version()}')
    print('Waiting for a card...')
    uid = reader.wait_for_card(timeout=30)
    print(f'Card UID: {uid}')

    reader.authenticate_sector(sector=1, key=DEFAULT_KEY, key_type='A')
    data = reader.read_block(0, raw=True)
    print(f'Sector 1, block 0: {data.hex()}')
    print(f'            ascii: {data.decode("ascii", "replace")}')
