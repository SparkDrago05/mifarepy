# mifarepy

**mifarepy** is a Python library for interfacing with PROMAG RFID readers using the
GNetPlus® serial protocol. It targets MIFARE Classic readers connected over RS-232/USB
and exposes every documented command through a clean, typed Python API.

---

## Features

| Category | What you get |
|---|---|
| **Card detection** | `get_uid()`, `get_uid_int()`, `scan_tag()`, `is_card_present()`, `ping()`, `wait_for_card()`, `wait_for_card_async()` |
| **Authentication** | `authenticate_sector()` (SAVE_KEY + AUTHENTICATE), `authenticate_sector_cached()` (AUTHENTICATE_KEY, skip reload) |
| **Block I/O** | `read_block()`, `write_block()`, `read_sector()`, `write_sector()`, `write_sector_uniform()` |
| **Bulk I/O** | `read_blocks()` / `write_blocks()` with per-sector `SectorAuth` |
| **Value blocks** | `create_value_block()`, `read_value()`, `write_value()`, `increment_value()`, `decrement_value()`, `transfer()`, `restore()` |
| **Reader control** | `get_version()`, `set_auto_mode()`, `halt()`, `rf_power()` |
| **Async** | `wait_for_card_async()` — non-blocking asyncio support |
| **Type safety** | `@overload` on `read_block` / `get_second_sn`, `Literal['A','B']`, `SectorAuth`, `CardInfo` |
| **Error detail** | `InvalidMessage.raw_bytes`, `GNetPlusError.nak_code` |

---

## Quick start

```python
from mifarepy import MifareReader

KEY = bytes.fromhex('FFFFFFFFFFFF')   # factory default

with MifareReader('/dev/ttyUSB0') as reader:
    print('Reader:', reader.get_version())
    print('Card UID:', reader.get_uid())         # e.g. '0xEDCEF8C3'

    reader.authenticate_sector(0, KEY)
    data = reader.read_sector(combine=True)      # 48-char hex string
    print('Sector 0 data:', data)
```

---

## Installation

```bash
pip install mifarepy
```

See [Installation](installation.md) for more options.

---

## Navigation

- [Installation](installation.md) — pip, from source, Raspberry Pi setup
- [Usage Guide](usage.md) — all APIs explained with worked examples
- [API Reference](api.md) — complete method signatures and docstrings
- [Examples](examples.md) — 9 runnable example scripts
