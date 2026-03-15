"""
Example 09 — RF power cycling to recover a frozen / stuck card
==============================================================
Occasionally a card ends up in an inconsistent state after an aborted
transaction and stops responding to REQUEST.  Cycling the RF field
(off → brief pause → on) forces the card to reset its internal state
machine so it becomes responsive again.

This example wraps a generic "operation" in a retry-with-RF-reset loop.

Usage:
    python 09_rf_power_reset.py [port]
"""

import sys
import time

from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError, InvalidMessage

PORT = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'

# How many times to attempt after an RF reset before giving up.
MAX_RETRIES = 3
# How long (seconds) to leave the field off before re-energising the card.
RF_OFF_DURATION = 0.1


def rf_reset(reader: MifareReader) -> None:
    """Turn the RF field off, wait briefly, and turn it back on."""
    reader.rf_power(False)
    time.sleep(RF_OFF_DURATION)
    reader.rf_power(True)
    # Give the card time to power back up.
    time.sleep(0.05)


def read_block_with_reset(reader: MifareReader, block: int, sector: int, key: bytes) -> str:
    """Authenticate and read a block, retrying after an RF reset on failure."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            uid = reader.get_uid()
            print(f'  Card UID: {uid}')
            reader.authenticate_sector(sector=sector, key=key, key_type='A')
            data = reader.read_block(block)
            return data.upper() if isinstance(data, str) else data.hex(' ')
        except (GNetPlusError, InvalidMessage) as exc:
            print(f'  Attempt {attempt} failed: {exc}')
            if attempt < MAX_RETRIES:
                print('  RF power cycling …')
                rf_reset(reader)
            else:
                raise RuntimeError(
                    f'Failed to read block {block} after {MAX_RETRIES} attempts.'
                ) from exc
    return ''  # unreachable


def main() -> None:
    with MifareReader(port=PORT) as reader:
        print(f'Connected on {PORT}')

        # ------------------------------------------------------------------ #
        # Demo 1 – Manual RF cycle                                            #
        # ------------------------------------------------------------------ #
        print('\n[Demo 1] Manual RF field off → on')
        reader.rf_power(False)
        print('  RF field OFF — card should be unresponsive now.')
        time.sleep(0.5)
        reader.rf_power(True)
        print('  RF field ON  — card is powered again.')
        time.sleep(0.1)

        # ------------------------------------------------------------------ #
        # Demo 2 – Retry-with-reset wrapper                                   #
        # ------------------------------------------------------------------ #
        print('\n[Demo 2] Read block 1 with automatic RF reset on error')
        print('Place a card on the reader and press Enter …')
        input()

        DEFAULT_KEY = bytes([0xFF] * 6)
        SECTOR_FOR_BLOCK_1 = 0  # block 1 belongs to sector 0
        try:
            data = read_block_with_reset(reader, block=1, sector=SECTOR_FOR_BLOCK_1, key=DEFAULT_KEY)
            print(f'  Block 1 data: {data}')
        except RuntimeError as exc:
            print(f'  Error: {exc}')

        # ------------------------------------------------------------------ #
        # Demo 3 – Field-cycle before every transaction (hardened loop)       #
        # ------------------------------------------------------------------ #
        print('\n[Demo 3] Hardened polling loop — RF reset between each scan')
        print('Press Ctrl-C to stop.\n')
        try:
            while True:
                rf_reset(reader)
                try:
                    uid = reader.get_uid()
                    print(f'  Card: {uid}')
                except (GNetPlusError, InvalidMessage):
                    print('  (no card)')
                time.sleep(1)
        except KeyboardInterrupt:
            print('\nStopped.')


if __name__ == '__main__':
    main()
