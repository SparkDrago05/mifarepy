# Usage Guide

This guide covers every major feature of **mifarepy** and is structured so you can read it top-to-bottom or jump directly to a section.

---

## Opening a connection

```python
from mifarepy import MifareReader

# context manager (recommended — closes port automatically)
with MifareReader('/dev/ttyUSB0') as reader:
    ...

# explicit open / close
reader = MifareReader('/dev/ttyUSB0')
try:
    ...
finally:
    reader.close()
```

`MifareReader` accepts the same keyword arguments as `serial.Serial` (e.g. `timeout=`).

```python
print(repr(reader))
# MifareReader(port='/dev/ttyUSB0', baudrate=19200, addr=0, open)
```

---

## Reader information

```python
version = reader.get_version()
print(version)   # 'PGM0487 V1.4R0 (Build:110609)'
```

---

## Card detection

### One-shot UID

```python
uid   = reader.get_uid()       # '0xEDCEF8C3'  (REQUEST + ANTI_COLLISION)
uid_i = reader.get_uid_int()   # 3989956803
```

`get_sn()` still works but emits a `DeprecationWarning` — migrate to `get_uid()`.

### Quick check

```python
if reader.is_card_present():
    print('card found')
```

### Full scan (REQUEST → ANTI_COLLISION → SELECT)

```python
from mifarepy import CardInfo

card: CardInfo = reader.scan_tag()
print(card)           # '0xEDCEF8C3'
print(card.uid_int)   # 3989956803
print(card.uid_bytes) # b'\xc3\xf8\xce\xed'
```

### Wait for card (blocking / async)

```python
uid = reader.wait_for_card(timeout=10)         # blocking

import asyncio
uid = asyncio.run(reader.wait_for_card_async(timeout=10))   # asyncio
```

### Heartbeat

```python
alive = reader.ping()   # True if reader responds to POLLING
```

---

## MIFARE Classic memory layout

MIFARE Classic 1K cards have **16 sectors × 4 blocks × 16 bytes** = 1024 bytes.

```
Sector  Blocks (absolute)   Contents
  0       0, 1, 2, 3        Data (0-2) + Sector Trailer (3)
  1       4, 5, 6, 7        Data (0-2) + Sector Trailer (3)
  ...
 15      60,61,62,63        Data (0-2) + Sector Trailer (3)
```

The **sector trailer** (relative block 3) contains Key A, access bits, and Key B.  
mifarepy never writes block 3 through `write_sector()` or `write_sector_uniform()`
— you must call `write_block(3, ...)` explicitly if you need to change keys.

---

## Authentication

### Standard (SAVE_KEY + AUTHENTICATE)

```python
KEY_A = bytes.fromhex('FFFFFFFFFFFF')

reader.authenticate_sector(
    sector=1,
    key=KEY_A,
    key_type='A',    # 'A' or 'B'
    timeout=1.0,
    flush=True,
)
```

`authenticate_sector` automatically calls `select_card()` first, so it is safe to
call immediately after any write operation.

### Cached (skip key reload)

```python
# After authenticate_sector has already loaded a key once:
reader.authenticate_sector_cached(sector=2, key_type='A')
```

`authenticate_sector_cached` uses AUTHENTICATE_KEY (opcode 0x2E) and skips
SAVE_KEY, saving ~50 ms per sector when the same key is reused.

---

## Reading and writing

### Single block

```python
reader.authenticate_sector(sector=1, key=KEY_A)

# hex string (default)
hex_str: str   = reader.read_block(0)

# raw bytes
raw: bytes     = reader.read_block(0, raw=True)

# write (16 bytes or 32-char hex)
reader.write_block(0, b'\x00' * 16)
reader.write_block(0, '00' * 16)
```

### Sector-level

```python
# read blocks 0, 1, 2 as a dict
result: dict = reader.read_sector(sector=1)
# {0: 'aabb...', 1: '...', 2: '...'}

# combine into single string
combined: str   = reader.read_sector(combine=True)
combined: bytes = reader.read_sector(raw=True, combine=True)  # 48 bytes

# write same data to all 3 data blocks
reader.write_sector(b'\x00' * 16)           # uniform — 16 bytes, repeated
reader.write_sector(b'\x00' * 48)           # split — 48 bytes → blocks 0/1/2
reader.write_sector({0: b'\xAA'*16, 2: b'\xBB'*16})   # selective dict

# explicit uniform helper (intent-revealing)
reader.write_sector_uniform(b'\x00' * 16)
```

### Bulk cross-sector I/O

```python
from mifarepy import SectorAuth

# New-style with SectorAuth
results = reader.read_blocks(
    {1: [0, 1], 2: [0]},
    auth={
        1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
        2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
    },
)

# Legacy-style (still supported)
results = reader.read_blocks(
    {1: [0, 1], 2: [0]},
    keys=bytes.fromhex('FFFFFFFFFFFF'),
    key_types='A',
)

# Write
reader.write_blocks(
    {1: {0: b'\xAA'*16, 1: b'\xBB'*16}, 2: {0: b'\xCC'*16}},
    auth={
        1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
        2: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
    },
)
```

---

## Value blocks

Value blocks are a special MIFARE format that stores a signed 32-bit integer with
built-in redundancy (stored three times: value, inverted value, value again).

```python
reader.authenticate_sector(sector=2, key=KEY_A)

# Initialise
reader.create_value_block(block=0, initial_value=1000)

# Read
balance: int = reader.read_value(block=0)   # signed int

# Arithmetic
reader.increment_value(block=0, delta=50)
reader.decrement_value(block=0, delta=10)

# Overwrite
reader.write_value(block=0, value=9999)

# Copy between blocks (same sector)
reader.transfer(source_block=0, dest_block=1)

# Re-commit (repair after partial failure)
reader.restore(block=0)
```

---

## Reader control

```python
# RF field power (useful for card reset without physical removal)
reader.rf_power(False)   # off
reader.rf_power(True)    # on

# Put card in HALT state (multi-card anti-collision)
reader.halt()

# Auto-mode: reader sends EVN events on card arrival/departure
reader.set_auto_mode(True)    # enable
reader.set_auto_mode(False)   # disable (called automatically by close())
```

---

## Error handling

```python
from mifarepy import GNetPlusError, InvalidMessage

try:
    reader.authenticate_sector(0, KEY_A)
except GNetPlusError as e:
    print(e.code_description)   # 'Authentication failed'
    print(e.nak_code)           # 0x05
    print(repr(e.raw))          # b'\x05'

try:
    from mifarepy.protocol import Message
    msg = Message.readfrom(serial_port)
except InvalidMessage as e:
    print(e)                    # human error description
    print(e.raw_bytes.hex())    # partial bytes received before failure
```

---

## Type safety

```python
from typing import reveal_type

# @overload: IDE knows exact return type
hex_str = reader.read_block(0, raw=False)   # str
raw     = reader.read_block(0, raw=True)    # bytes

# SectorAuth validates at construction time
from mifarepy import SectorAuth
SectorAuth(key=b'\xFF'*5)          # ValueError: key must be exactly 6 bytes
SectorAuth(key=b'\xFF'*6, key_type='C')  # ValueError: key_type must be 'A' or 'B'
```
