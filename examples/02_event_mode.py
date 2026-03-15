"""
Example 02 — Event mode: wait for a card-insert notification
=============================================================
Enables the reader's automatic event mode so the hardware emits an EVN
message when a card enters the RF field.  Blocks up to `TIMEOUT` seconds
for that event, then reads the UID.

Usage:
    python 02_event_mode.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT    = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
TIMEOUT = 30  # seconds

with MifareReader(port=PORT) as reader:
    print(f'Listening for card on {PORT} (timeout={TIMEOUT}s) …')

    try:
        uid = reader.wait_for_card(timeout=TIMEOUT)
        print(f'Card detected! UID = {uid}')
    except TimeoutError:
        print('No card detected within the timeout.')
    except GNetPlusError as exc:
        print(f'Reader error: {exc}  [{exc.code_description}]')
