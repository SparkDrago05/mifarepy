# Usage Guide

This guide covers every major feature of **mifarepy** and is structured so you can read it top-to-bottom or jump directly to a section.

---

## Opening a connection

```python
from mifarepy import MifareReader

# find the reader automatically (recommended)
with MifareReader.auto() as reader:
    print(reader.port)            # e.g. '/dev/ttyUSB0' or 'COM3'

# or name the port yourself
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

`MifareReader.auto()` looks for the Prolific PL2303 USB-serial chip used in
PROMAG readers and checks that the device answers before returning it. If no
reader is found it raises `ReaderNotFoundError`, listing the serial ports it
saw. Pass `include_all=True` to also try other serial ports (for example an
RS-232 adapter with a different chip). See
[Hardware & setup](hardware.md#find-the-reader-automatically).

No reader at hand? `MifareReader.simulated()` connects to a built-in
simulator. See [Testing without hardware](testing.md).

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

!!! tip
    New to sectors, keys and access bits? Read the [MIFARE Classic primer](mifare-classic.md) first.

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

The sector helpers use the layout of the sector you last authenticated. On a
MIFARE Classic 4K card, sectors 32–39 have 15 data blocks, so after
`authenticate_sector(35, key)` the call `read_sector()` returns blocks 0–14.
Pass `sector=` to choose the layout explicitly.

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

Increment and decrement read the value and write the new one. Transfer and
restore use the reader's native RESTORE/TRANSFER commands and then read the
block back to confirm the result; if a reader does not support those
commands, mifarepy falls back to writing the value directly. You can pick one
behaviour explicitly:

```python
MifareReader('/dev/ttyUSB0', value_ops='auto')      # default: as described above
MifareReader('/dev/ttyUSB0', value_ops='native')    # native only (incl. SET_VALUE); raise on any problem
MifareReader('/dev/ttyUSB0', value_ops='software')  # read-modify-write only (pre-3.1 behaviour)
```

!!! warning "Native increment/decrement"
    `value_ops='native'` sends SET_VALUE for increment and decrement. PCR310U
    firmware `PGM0487 V1.4R0` computes it wrongly for most deltas, so test it
    on your reader (`reader.get_version()`) before relying on it.

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

When the reader rejects a command, mifarepy raises a specific subclass of
`GNetPlusError`, with the context and a hint on how to fix it:

```text
mifarepy.AuthenticationError: NAK received — Authentication error (sector 3, key A) (raw=b'\x04')
Hint: The key or key type is wrong for this sector. Check the 6-byte key and
whether the sector expects Key A or Key B. New cards use FFFFFFFFFFFF.
```

| Exception | When | NAK codes |
|---|---|---|
| `NoCardError` | No card on the reader | `0x1F`, `0x03` |
| `AuthenticationError` | Wrong key or key type | `0x04`, `0x09` |
| `NotAuthenticatedError` | Block accessed before authenticating its sector | `0x0A` |
| `CardReadError` / `CardWriteError` | Read or write refused (access conditions, card moved) | `0x12` / `0x0F` |
| `ValueBlockError` | Value operation failed | `0x0E`, `0x10`, `0x11` |
| `CardTimeoutError` | Card stopped answering | `0x1C` |
| `ReaderProtocolError` | Command or parameter not accepted by the reader | `0x27`, `0xE0`–`0xE6` |
| `ReaderAccessError` | Reader needs a logon or host key | `0x2D`, `0x2F`, `0x33` |

All of them are `GNetPlusError`, so existing `except GNetPlusError` code keeps
working. Catch the specific ones when you want to react differently:

```python
from mifarepy import AuthenticationError, GNetPlusError, InvalidMessage, NoCardError

try:
    reader.authenticate_sector(0, KEY_A)
except NoCardError:
    print('Please tap your card')
except AuthenticationError as e:
    print('Wrong key:', e.hint)
except GNetPlusError as e:
    print(e.code_description)   # e.g. 'Read error'
    print(hex(e.nak_code))      # e.g. 0x12
    print(repr(e.raw))          # b'\x12'

try:
    from mifarepy.protocol import Message
    msg = Message.readfrom(serial_port)
except InvalidMessage as e:
    print(e)                    # human error description
    print(e.raw_bytes.hex())    # partial bytes received before failure
```

---

Opening a port that doesn't exist, is busy, or that you may not access raises
`ReaderConnectionError` (a `RuntimeError`) with a hint, such as joining the
`dialout` group on Linux.

See the [error code table](protocol.md#error-codes) for every NAK code the
reader can return, and [troubleshooting](hardware.md#troubleshooting) for
common fixes.

---

## Frame tracing

To see exactly what goes over the wire, turn on tracing:

```python
from mifarepy import MifareReader, enable_wire_trace

enable_wire_trace()                 # prints to stderr
with MifareReader.auto() as reader:
    reader.authenticate_sector(1, KEY_A)
```

```text
10:42:01.512 TX SELECT_CARD      01 00 22 04 | 34 C6 9B D3 | E2 28
10:42:01.530 RX ACK              01 00 06 01 | 08 | 73 E0
10:42:01.531 TX SAVE_KEY         01 00 2B 08 | 60 01 ** ** ** ** ** ** | 82 90
10:42:01.598 RX ACK              01 00 06 00 |  | 60 72
10:42:01.599 TX AUTHENTICATE     01 00 23 02 | 60 01 | 84 67
10:42:01.615 RX NAK 0x04         01 00 15 01 | 04 | B3 11   Authentication error
```

Keys are shown as `**`. Pass `show_keys=True` to print them, but only on test
cards. Frames are logged on the `mifarepy.wire` logger at DEBUG level, so you
can also route them through your own logging setup.

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
