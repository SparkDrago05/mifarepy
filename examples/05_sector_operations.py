"""
Example 05 — Read and write an entire sector
=============================================
Uses ``read_sector`` and ``write_sector`` to operate on all three data
blocks of a sector in a single convenient call.

The sector trailer (block 3) is never touched by these helpers.

Usage:
    python 05_sector_operations.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT        = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
SECTOR      = 2
DEFAULT_KEY = bytes.fromhex('FFFFFFFFFFFF')


def print_sector(label: str, data: dict) -> None:
    print(f'{label}:')
    for blk, content in sorted(data.items()):
        print(f'  Block {blk}: {content.upper() if isinstance(content, str) else content.hex().upper()}')


with MifareReader(port=PORT) as reader:
    print(f'Connected on {PORT}')
    input('Place card and press Enter …')

    uid = reader.get_uid()
    print(f'Card UID: {uid}\n')

    # --- Authenticate ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print(f'Sector {SECTOR} authenticated.')

    # --- Read entire sector (blocks 0-2) ---
    original = reader.read_sector(sector=SECTOR, raw=True)
    print_sector(f'\nSector {SECTOR} original', original)

    # --- Write three different blocks at once using a 48-byte blob ---
    payload = (
        b'\xAA' * 16 +   # block 0
        b'\xBB' * 16 +   # block 1
        b'\xCC' * 16     # block 2
    )
    print(f'\nWriting 48-byte blob to sector {SECTOR} …')
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    reader.write_sector(payload)
    print('Done.')

    # --- Read back ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    updated = reader.read_sector(sector=SECTOR, raw=True)
    print_sector(f'\nSector {SECTOR} after write', updated)

    # --- Restore using per-block dict ---
    print('\nRestoring original data via per-block dict …')
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    reader.write_sector({blk: data for blk, data in original.items()})
    print('Done.')
