"""
Example 04 — Authenticate a sector, read and write a single block
=================================================================
Demonstrates the full authenticate → read → write → verify cycle for
a single 16-byte block.

MIFARE Classic 1K layout reminder:
  Sector 0: blocks 0, 1, 2 (data), 3 (trailer with keys & access bits)
  Sector 1: blocks 4, 5, 6 (data), 7 (trailer)
  …

Blocks 0-2 within each sector are safe to write.
Block 3 (the trailer) stores Key A, access bits, and Key B — only modify
it if you know what you're doing, or you will lock yourself out.

Usage:
    python 04_read_write_block.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT       = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
SECTOR     = 1           # sector to authenticate
BLOCK      = 0           # block index relative to sector (0-2)
DEFAULT_KEY = bytes.fromhex('FFFFFFFFFFFF')  # factory default Key A

with MifareReader(port=PORT) as reader:
    print(f'Connected on {PORT}')
    print('Place card on reader …')
    input('Press Enter when ready.')

    # --- 1. Get UID ---
    uid = reader.get_uid()
    print(f'\nCard UID: {uid}')

    # --- 2. Authenticate sector ---
    print(f'Authenticating sector {SECTOR} with default Key A …')
    try:
        reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
        print('  Authentication successful.')
    except GNetPlusError as exc:
        print(f'  Authentication failed: {exc}  [{exc.code_description}]')
        sys.exit(1)

    # --- 3. Read current block content ---
    raw_data = reader.read_block(BLOCK, raw=True)
    print(f'\nBlock {BLOCK} (current): {raw_data.hex().upper()}')

    # --- 4. Write new data ---
    new_data = b'\xDE\xAD\xBE\xEF' * 4   # 16 bytes
    print(f'Writing:                {new_data.hex().upper()} …')
    reader.write_block(BLOCK, new_data)
    print('  Write sent.')

    # --- 5. Read back and verify ---
    verify = reader.read_block(BLOCK, raw=True)
    print(f'Block {BLOCK} (readback): {verify.hex().upper()}')

    if verify == new_data:
        print('\nVerification PASSED.')
    else:
        print('\nVerification FAILED — data mismatch!')

    # --- 6. Restore original data ---
    print('Restoring original data …')
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    reader.write_block(BLOCK, raw_data)
    print('Done.')
