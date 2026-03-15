# API Reference

Complete reference for all public classes, dataclasses, exceptions, and methods in
**mifarepy v3.0**.

---

## Protocol module (`mifarepy.protocol`)

### `InvalidMessage`

```python
class InvalidMessage(Exception):
    raw_bytes: bytes  # partial bytes received before the error
```

Raised when a frame read from the serial port is malformed (wrong SOH, CRC mismatch,
truncated data).  `raw_bytes` holds whatever *was* read so you can inspect it during
debugging.

---

### `GNetPlusError`

```python
class GNetPlusError(Exception):
    raw: bytes               # raw NAK payload (typically 1 byte)
    code_description: str    # human-readable description from NAK code table
    nak_code: int            # integer value of raw[0], or 0 if multi-byte
```

Raised when the reader sends a NAK response.

**NAK code table:**

| Code | Meaning |
|------|---------|
| `0x01` | Invalid address |
| `0x02` | Invalid message length |
| `0x03` | Invalid command |
| `0x04` | Card not present |
| `0x05` | Authentication failed |
| `0x06` | Block read failed |
| `0x07` | Block write failed |
| `0x08` | Value read failed |
| `0x09` | Value write failed |
| `0x0A` | Access condition violation |
| `0x0B` | Key not found |
| `0x0C` | Timeout |

---

### `SectorAuth`

```python
@dataclass
class SectorAuth:
    key: bytes                        # 6-byte MIFARE authentication key (required)
    key_type: Literal['A', 'B'] = 'A'
    timeout: float = 1.0
    flush: bool = True
```

Per-sector authentication configuration used with the `auth=` parameter of
`read_blocks()` / `write_blocks()`.  Validates `key_type` and `key` length at
construction time.

```python
from mifarepy import SectorAuth

sa = SectorAuth(
    key=bytes.fromhex('A0A1A2A3A4A5'),
    key_type='B',
    timeout=2.0,
)
```

---

### `CardInfo`

```python
@dataclass
class CardInfo:
    uid: str          # '0xAABBCCDD' (always 10 chars, upper-case)
    uid_int: int      # unsigned 32-bit integer
    uid_bytes: bytes  # raw 4-byte ANTI_COLLISION response (little-endian)
```

Returned by `scan_tag()`.

```python
card = reader.scan_tag()
str(card)         # '0xEDCEF8C3'
repr(card)        # "CardInfo(uid='0xEDCEF8C3')"
card.uid_int      # 3989956803
card.uid_bytes    # b'\xc3\xf8\xce\xed'
```

---

### `Message` / `QueryMessage` / `ResponseMessage`

Low-level GNetPlus® frame classes.  You rarely need these directly.

| Constant | Opcode | Description |
|---|---|---|
| `POLLING` | `0x00` | Heartbeat / connectivity check |
| `GET_VERSION` | `0x01` | Read firmware version string |
| `REQUEST` | `0x20` | ISO 14443-3 REQUEST — wake IDLE cards |
| `ANTI_COLLISION` | `0x21` | Get UID from a single card |
| `SELECT_CARD` | `0x22` | Select a specific card by UID |
| `AUTHENTICATE` | `0x23` | Authenticate a sector (after SAVE_KEY) |
| `READ_BLOCK` | `0x24` | Read a 16-byte block |
| `WRITE_BLOCK` | `0x25` | Write a 16-byte block |
| `READ_VALUE` | `0x27` | Read a signed 32-bit value block |
| `CREATE_VALUE_BLOCK` | `0x28` | Create/update a value block |
| `ACCESS_CONDITION` | `0x29` | Set sector access conditions |
| `HALT` | `0x2A` | Put card into HALT state |
| `SAVE_KEY` | `0x2B` | Load authentication key into reader |
| `GET_SECOND_SN` | `0x2C` | Read 7-byte secondary UID |
| `GET_ACCESS_CONDITION` | `0x2D` | Read sector access conditions |
| `AUTHENTICATE_KEY` | `0x2E` | Authenticate using already-loaded key |
| `REQUEST_ALL` | `0x2F` | Wake ALL cards including HALT state |
| `RF_POWER_ONOFF` | `0x3E` | Toggle RF field power |
| `AUTO_MODE` | `0x3F` | Enable/disable EVN event notifications |

### `gencrc(msg_bytes)`

```python
def gencrc(msg_bytes: bytes) -> int: ...
```

Compute the 16-bit CRC checksum used by the GNetPlus® protocol.

---

## Reader module (`mifarepy.reader`)

### `MifareReader`

```python
class MifareReader:
    port: str
    baudrate: int
    deviceaddr: int
```

Main entry point.  All methods are synchronous unless noted.

---

#### Constructor

```python
MifareReader(
    port: str = '/dev/ttyUSB0',
    baudrate: int = 19200,
    deviceaddr: int = 0,
    **kwargs,   # forwarded to serial.Serial
)
```

`**kwargs` is forwarded verbatim to `serial.Serial`, so you can pass `timeout=`,
`bytesize=`, etc.

Raises `RuntimeError` if the port cannot be opened.

---

#### Context manager / `__repr__`

```python
with MifareReader('/dev/ttyUSB0') as reader:
    ...

repr(reader)
# "MifareReader(port='/dev/ttyUSB0', baudrate=19200, addr=0, open)"
```

`close()` disables auto mode before closing the port to avoid spurious EVN events
in the next session.

---

### Card detection

#### `get_uid() -> str`

Run **REQUEST → ANTI_COLLISION** and return the UID as `'0xAABBCCDD'`.
Does not call SELECT — use `scan_tag()` when you need an active card.

```python
uid = reader.get_uid()   # '0xEDCEF8C3'
```

#### `get_uid_int() -> int`

Same as `get_uid()` but returns an unsigned 32-bit integer.

```python
n = reader.get_uid_int()   # 3989956803
```

#### `get_sn(endian='little', as_string=True)` *(deprecated)*

> **Deprecated in v3.0.** Use `get_uid()` or `get_uid_int()` instead.

The `endian` parameter lets you choose byte order, which was confusing.  The new
methods always use little-endian (matching `struct.pack('<L', ...)`).

#### `request_all(endian='little', as_string=True) -> Union[str, int]`

**REQUEST_ALL → ANTI_COLLISION** — wakes cards that are in HALT state.

#### `get_second_sn(as_string=True) -> Union[str, bytes]`

Read the 7-byte secondary UID (MIFARE Ultralight / DESFire).

```python
@overload
def get_second_sn(self, as_string: Literal[True]) -> str: ...
@overload
def get_second_sn(self, as_string: Literal[False]) -> bytes: ...
```

#### `select_card() -> bytes`

**REQUEST → ANTI_COLLISION → SELECT_CARD**.  Returns the ACK payload.
Called automatically by `authenticate_sector()` — only call this directly for
advanced multi-card workflows.

#### `scan_tag() -> CardInfo`

One-shot: **REQUEST → ANTI_COLLISION → SELECT_CARD**.  Returns a
`CardInfo` dataclass.  The card is left in the *active* state.

```python
card = reader.scan_tag()
print(card)           # '0xEDCEF8C3'
print(card.uid_int)   # 3989956803
```

#### `ping() -> bool`

Send **POLLING** (opcode `0x00`) and return `True` if the reader acknowledges.
Use this to verify the serial connection without interacting with any card.

```python
if not reader.ping():
    raise RuntimeError('Reader not responding')
```

#### `is_card_present() -> bool`

Non-blocking: send a single **REQUEST** and return `True` if a card responded.
Does not select or authenticate the card.

```python
while not reader.is_card_present():
    time.sleep(0.1)
```

#### `wait_for_card(timeout=10) -> Optional[str]`

Enable auto mode and block until a card arrives or `timeout` seconds elapse.
Returns the card UID string.  Raises `TimeoutError`.

#### `wait_for_card_async(timeout=10.0) -> str` *(async)*

Non-blocking asyncio variant.  Runs the blocking I/O in a thread-pool executor.

```python
import asyncio

async def main():
    with MifareReader('/dev/ttyUSB0') as reader:
        uid = await reader.wait_for_card_async(timeout=15)
        print('Card:', uid)

asyncio.run(main())
```

---

### Authentication

#### `authenticate_sector(sector, key, key_type='A', timeout=1.0, flush=True)`

Load a key into the reader **(SAVE_KEY)** and authenticate a sector **(AUTHENTICATE)**.

- Calls `select_card()` first — safe to call after any write operation.
- `key` must be exactly 6 bytes.
- `key_type` must be `'A'` or `'B'`.

```python
reader.authenticate_sector(
    sector=1,
    key=bytes.fromhex('FFFFFFFFFFFF'),
    key_type='A',
)
```

#### `authenticate_sector_cached(sector, key_type='A', timeout=1.0)`

Authenticate using the key that is **already loaded** in the reader
(AUTHENTICATE_KEY, opcode `0x2E`).  Skips SAVE_KEY — faster for repeat-sector access
with the same key.

> **Warning:** The reader stores only one key at a time.  If any other sector was
> authenticated between the last `authenticate_sector` call and this one, call
> `authenticate_sector` again.

---

### Single-block I/O

#### `read_block(block, raw=False) -> Union[bytes, str]`

Read a 16-byte block relative to the currently authenticated sector.

```python
@overload
def read_block(self, block: int, raw: Literal[True]) -> bytes: ...
@overload
def read_block(self, block: int, raw: Literal[False] = ...) -> str: ...
```

`block` is relative to the sector (0–3; block 3 is the sector trailer).

#### `write_block(block, data) -> str`

Write exactly 16 bytes.  `data` can be `bytes` or a 32-character hex string.
Returns the reader's echoed ACK payload as a hex string.

---

### Sector-level I/O

#### `read_sector(sector=None, raw=False, combine=False)`

Read blocks 0, 1, and 2 of the authenticated sector.  Block 3 (trailer) is skipped.

- `combine=False` (default) → `{0: '...', 1: '...', 2: '...'}`
- `combine=True, raw=False` → single 96-char hex string
- `combine=True, raw=True` → 48-byte `bytes` object

#### `write_sector(data)`

Write data to blocks 0–2.  Accepts:

- **16 bytes** (or 32-char hex) → same blob to all 3 blocks
- **48 bytes** (or 96-char hex) → split into three 16-byte chunks
- **`dict`** mapping `{0: ..., 1: ..., 2: ...}` → write only specified blocks

#### `write_sector_uniform(data)`

Explicit, intent-revealing alias for the 16-byte path of `write_sector()`.
Writes the same 16 bytes to blocks 0, 1, and 2.

```python
reader.write_sector_uniform(b'\x00' * 16)
```

---

### Bulk cross-sector I/O

#### `read_blocks(mapping, *, raw=False, combine=False, auth=None, keys=None, key_types='A', timeout=1.0, flush=True)`

```python
mapping: dict[int, list[int]]          # {sector: [block, block, ...]}
auth: Optional[dict[int, SectorAuth]]  # new-style per-sector auth
keys: ...                              # legacy — global or per-sector key bytes
```

Returns `{sector: {block: data}}`, or combined bytes/string when `combine=True`.

```python
results = reader.read_blocks(
    {1: [0, 1, 2], 3: [0]},
    auth={
        1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
        3: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
    },
)
```

#### `write_blocks(mapping, *, auth=None, keys=None, key_types='A', timeout=1.0, flush=True)`

```python
mapping: dict[int, Union[bytes, str, dict[int, Union[str, bytes]]]]
auth: Optional[dict[int, SectorAuth]]
```

Same `auth=` / legacy style support as `read_blocks`.

---

### Value block operations

Value blocks store a signed 32-bit integer in MIFARE redundant format.
Authenticate the sector before any value block operation.

#### `create_value_block(block, initial_value=0)`

Initialize a block as a value block.  Uses **CREATE_VALUE_BLOCK** (opcode `0x28`).

#### `read_value(block) -> int`

Read a signed 32-bit value.  Uses **READ_VALUE** (opcode `0x27`).

#### `write_value(block, value)`

Write a signed 32-bit value.  Delegates to `create_value_block` for compatibility
with all firmware versions.

#### `increment_value(block, delta)`

Add `delta` (must be > 0) to the stored value.  Read-modify-write.
Raises `ValueError` on int32 overflow.

#### `decrement_value(block, delta)`

Subtract `delta` from the stored value.  Raises `ValueError` on int32 underflow.

#### `transfer(source_block, dest_block)`

Copy value from `source_block` to `dest_block` within the same authenticated sector.

#### `restore(block)`

Re-read and re-write a block to ensure value block format integrity.

---

### Reader control

#### `get_version() -> str`

Return the firmware/hardware version string.

```python
reader.get_version()   # 'PGM0487 V1.4R0 (Build:110609)'
```

#### `set_auto_mode(enabled=True) -> bytes`

Enable (`True`) or disable (`False`) event-notification mode.  When enabled, the
reader spontaneously sends **EVN** frames on card arrival / departure.

#### `halt()`

Send **HALT** to put the current card into HALT state.  The card will only respond
to `request_all()` until it is removed and re-presented.

#### `rf_power(on: bool)`

Toggle the RF field.  Power off + on resets cards that are in an inconsistent state.

---

### Low-level helpers

#### `sendmsg(function, data=b'')`

Build and transmit a `QueryMessage`.

#### `readmsg(sink_events=False) -> ResponseMessage`

Read one `ResponseMessage`.  If `sink_events=True`, **EVN** frames are silently
discarded until a non-event frame arrives.  Raises `GNetPlusError` on **NAK**.

