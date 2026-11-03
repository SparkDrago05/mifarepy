# mifarepy

[![PyPI Version](https://img.shields.io/pypi/v/mifarepy.svg)](https://pypi.org/project/mifarepy/)
[![Python Versions](https://img.shields.io/pypi/pyversions/mifarepy.svg)](https://pypi.org/project/mifarepy/)
[![PyPI Downloads](https://static.pepy.tech/badge/mifarepy)](https://pepy.tech/projects/mifarepy)
[![Tests](https://github.com/SparkDrago05/mifarepy/actions/workflows/test.yml/badge.svg)](https://github.com/SparkDrago05/mifarepy/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/SparkDrago05/mifarepy/badges/coverage.json)](https://github.com/SparkDrago05/mifarepy/actions/workflows/test.yml)
[![Typed](https://img.shields.io/badge/typing-typed-blue.svg)](https://peps.python.org/pep-0561/)
[![License](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](LICENSE)

**Read, write and manage MIFARE® Classic cards from Python** with PROMAG and
other GIGA-TMS readers that speak the **GNetPlus®** serial protocol.
Typed, tested, and its only dependency is `pyserial`.

📖 **Documentation:** <https://sparkdrago05.github.io/mifarepy/>

## Install

```bash
pip install mifarepy
```

Requires Python 3.9 or newer. Works on Linux (including Raspberry Pi), Windows and macOS.

## Quick start

```python
from mifarepy import MifareReader

KEY = bytes.fromhex('FFFFFFFFFFFF')   # factory default key

with MifareReader('/dev/ttyUSB0') as reader:      # Windows: 'COM3'
    print('Reader:', reader.get_version())
    print('Card UID:', reader.get_uid())          # e.g. '0xEDCEF8C3'

    reader.authenticate_sector(1, KEY)
    print('Block 0:', reader.read_block(0))       # 32-char hex string
    reader.write_block(0, bytes(range(16)))
```

## Features

| | |
|---|---|
| **Card detection** | `get_uid()`, `scan_tag()`, `is_card_present()`, `wait_for_card()`, `wait_for_card_async()`, multi-card `request_all()` |
| **Authentication** | `authenticate_sector()` with Key A or B, `authenticate_sector_cached()` |
| **Block I/O** | `read_block()`, `write_block()`, `read_sector()`, `write_sector()` (never touches sector trailers) |
| **Bulk I/O** | `read_blocks()` / `write_blocks()` across sectors with per-sector `SectorAuth` keys |
| **Value blocks** | `create_value_block()`, `read_value()`, `increment_value()`, `decrement_value()`, `transfer()`, `restore()`, using native card operations that are verified by reading back |
| **Card layout** | MIFARE Classic 1K and 4K, including the 16-block sectors 32–39; `mifarepy.layout` helpers for block arithmetic |
| **Reader control** | `ping()`, `get_version()`, `set_auto_mode()`, `halt()`, `rf_power()` |
| **Developer experience** | Context manager, full type hints (`py.typed`), typed errors with readable NAK codes |

## Supported hardware

| Reader | Connection |
|---|---|
| PROMAG **PCR310U** | USB (PL2303 USB-serial) |
| PROMAG **MF5** / **MF10** | RS-232 / TTL serial |
| Other GNetPlus® readers | Serial |

Cards: MIFARE Classic 1K and 4K (13.56 MHz, ISO/IEC 14443 A).
See [Hardware & setup](https://sparkdrago05.github.io/mifarepy/hardware/) for finding the
port, Linux permissions and troubleshooting.

## Documentation

- [Usage guide](https://sparkdrago05.github.io/mifarepy/usage/): every feature with examples
- [MIFARE Classic primer](https://sparkdrago05.github.io/mifarepy/mifare-classic/): sectors, keys, access bits, value blocks
- [GNetPlus protocol reference](https://sparkdrago05.github.io/mifarepy/protocol/): frame format, CRC, commands, error codes
- [API reference](https://sparkdrago05.github.io/mifarepy/api/)
- [Examples](examples/): nine runnable scripts

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, ideas and pull requests are welcome. See the
[contributing guide](https://sparkdrago05.github.io/mifarepy/contributing/).

```bash
git clone https://github.com/SparkDrago05/mifarepy.git && cd mifarepy
pip install -e ".[dev]"
pytest && ruff check . && mypy
```

## Credits & license

Maintained by **Spark Drago** ([@SparkDrago05](https://github.com/SparkDrago05)).

mifarepy began as a Python 3 port of [gnetplus](https://github.com/harishpillay/gnetplus)
(© 2013 Red Hat Inc., by Chow Loong Jin and Harish Pillay) and has since grown into a
separate library.

Licensed under the **GNU Lesser General Public License v3.0 or later**. See
[LICENSE](LICENSE) and [COPYING](COPYING).

MIFARE® is a registered trademark of NXP B.V., and GNetPlus® is a trademark of GIGA-TMS Inc.
mifarepy is an independent project and is not affiliated with either company.
