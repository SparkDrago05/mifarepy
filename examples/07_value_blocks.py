"""
Example 07 — Value blocks: create, increment, decrement, transfer, restore
===========================================================================
MIFARE Classic value blocks store a signed 32-bit integer in a special
redundant format and support atomic hardware-level increment/decrement,
so you never need to read-modify-write.

Typical use cases:
  - Prepaid transit / fare cards
  - Loyalty point systems
  - Access credit counters

Layout:
  - Call ``create_value_block`` once to format the block.
  - Then use ``increment_value`` / ``decrement_value`` for mutations.
  - ``transfer`` copies a value from one block to another (e.g. backup).
  - ``restore`` reloads the last committed state (undo a partial change).

Usage:
    python 07_value_blocks.py [port]
"""

import sys
from mifarepy import MifareReader
from mifarepy.protocol import GNetPlusError

PORT        = sys.argv[1] if len(sys.argv) > 1 else '/dev/ttyUSB0'
SECTOR      = 4       # sector that will hold the value block
BLOCK       = 0       # block index within the sector (0-2)
BACKUP_BLK  = 1       # block to keep a backup copy via transfer
DEFAULT_KEY = bytes.fromhex('FFFFFFFFFFFF')


with MifareReader(port=PORT) as reader:
    print(f'Connected on {PORT}')
    input('Place card and press Enter …')

    uid = reader.get_uid()
    print(f'Card UID: {uid}')

    # Authenticate
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print(f'Sector {SECTOR} authenticated.\n')

    # --- Step 1: Create value block with initial value 1000 ---
    INITIAL = 1000
    print(f'Initialising block {BLOCK} as value block with value {INITIAL} …')
    reader.create_value_block(block=BLOCK, initial_value=INITIAL)
    print(f'  Done.  Current value: {reader.read_value(BLOCK)}')

    # --- Step 2: Increment ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print('\nAdding 250 …')
    reader.increment_value(BLOCK, 250)
    print(f'  Value after increment: {reader.read_value(BLOCK)}')

    # --- Step 3: Decrement ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print('Subtracting 100 …')
    reader.decrement_value(BLOCK, 100)
    print(f'  Value after decrement: {reader.read_value(BLOCK)}')

    # --- Step 4: Transfer to backup block ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print(f'\nCopying value to backup block {BACKUP_BLK} via transfer …')
    reader.transfer(source_block=BLOCK, dest_block=BACKUP_BLK)

    # Read backup
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    backup_val = reader.read_value(BACKUP_BLK)
    print(f'  Backup block {BACKUP_BLK} now holds: {backup_val}')

    # --- Step 5: Restore (reset to last committed state) ---
    reader.authenticate_sector(sector=SECTOR, key=DEFAULT_KEY, key_type='A')
    print(f'\nRestoring block {BLOCK} …')
    reader.restore(BLOCK)
    print(f'  Value after restore: {reader.read_value(BLOCK)}')
    print('\nDone.')
