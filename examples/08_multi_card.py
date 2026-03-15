"""
Example 08 — Multi-card enumeration using HALT + REQUEST_ALL
============================================================
Standard REQUEST only sees cards in the READY state.
After HALT a card enters the HALT state and becomes invisible to REQUEST.
REQUEST_ALL sees cards in BOTH states.

This example shows how to iterate over multiple cards placed on the
reader simultaneously:
  1. REQUEST (see first non-halted card)
  2. Read its UID
  3. HALT it (so we don't see it again on the next loop)
  4. REQUEST_ALL (see next card, including ones just halted)
  5. Repeat until no more unprocessed cards

Usage:
    python 08_multi_card.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError, InvalidMessage

PORT = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'

with MifareReader(port=PORT) as reader:
    print(f'Connected on {PORT}')
    print('Place one or more cards on the reader simultaneously.')
    input('Press Enter when ready …\n')

    seen_uids: list[str] = []

    # First sweep: REQUEST detects only non-halted cards.
    # Subsequent sweeps: REQUEST_ALL picks up halted cards too.
    first = True
    while True:
        try:
            if first:
                uid = reader.get_uid()
                first = False
            else:
                uid = reader.request_all(as_string=True)

            if uid in seen_uids:
                # Already processed this card; stop.
                break

            seen_uids.append(uid)
            print(f'  Found card: {uid}')

            # HALT this card so the next REQUEST_ALL reveals the next one.
            reader.halt()

        except (GNetPlusError, InvalidMessage):
            # No more cards responded.
            break

    if seen_uids:
        print(f'\nTotal cards detected: {len(seen_uids)}')
        for i, uid in enumerate(seen_uids, 1):
            print(f'  {i}. {uid}')
    else:
        print('No cards detected.')
