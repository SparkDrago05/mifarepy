"""
Example 06 — Bulk multi-sector read and write
==============================================
``read_blocks`` and ``write_blocks`` let you operate across multiple
sectors in a single call, with optional per-sector keys.

This is useful when you store structured data spanning sectors (e.g.
a name in sector 1, a balance in sector 2, an expiry in sector 3).

Usage:
    python 06_multi_sector_bulk.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT        = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
DEFAULT_KEY = bytes.fromhex('FFFFFFFFFFFF')

# Sectors and which blocks (relative 0-2) to read from each.
READ_MAPPING = {
    1: [0, 1],     # read blocks 0 and 1 from sector 1
    2: [0],        # read block 0 from sector 2
    3: [0, 1, 2],  # read all data blocks from sector 3
}

# Data to write: sector -> {block: 16-byte payload}
WRITE_MAPPING = {
    1: {
        0: b'Name:   Alice   ',   # exactly 16 bytes
        1: b'Role:   Admin   ',
    },
    2: {
        0: b'\x00' * 8 + b'\xFF' * 8,  # 16 bytes mixed
    },
}


with MifareReader(port=PORT) as reader:
    print(f'Connected on {PORT}')
    input('Place card and press Enter …')

    uid = reader.get_uid()
    print(f'Card UID: {uid}\n')

    # --- Bulk read across sectors (same key for all) ---
    print(f'Reading sectors {list(READ_MAPPING.keys())} …\n')
    try:
        results = reader.read_blocks(
            mapping=READ_MAPPING,
            raw=True,
            keys=DEFAULT_KEY,
            key_types='A',
        )
        for sector, blocks in results.items():
            for blk, data in blocks.items():
                print(f'  Sector {sector} Block {blk}: {data.hex().upper()}')
    except GNetPlusError as exc:
        print(f'Read failed: {exc}  [{exc.code_description}]')

    # --- Bulk write across sectors ---
    print(f'\nWriting to sectors {list(WRITE_MAPPING.keys())} …')
    try:
        reader.write_blocks(
            mapping=WRITE_MAPPING,
            keys=DEFAULT_KEY,
            key_types='A',
        )
        print('Write complete.')
    except GNetPlusError as exc:
        print(f'Write failed: {exc}  [{exc.code_description}]')

    # --- Per-sector keys example ---
    # If sectors use different keys you can pass a dict:
    #
    # reader.read_blocks(
    #     mapping={1: [0], 2: [0]},
    #     keys={1: bytes.fromhex('FFFFFFFFFFFF'), 2: bytes.fromhex('A0A1A2A3A4A5')},
    #     key_types={1: 'A', 2: 'B'},
    # )
