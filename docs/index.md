---
hide:
  - navigation
  - toc
---

<div class="mp-hero" markdown>

# mifarepy

Read, write and manage MIFARE® Classic cards from Python, using PROMAG and
other GIGA-TMS readers that speak the GNetPlus® serial protocol. Typed,
tested and dependency-light: the only dependency is `pyserial`.

[Get started](installation.md){ .md-button .md-button--primary }
[API reference](api.md){ .md-button }
[GitHub](https://github.com/SparkDrago05/mifarepy){ .md-button }

</div>

![Terminal demo: mifarepy prints the reader firmware, waits for a card, then shows its UID and reads block 0 of sector 1](assets/demo.gif)

```bash
pip install mifarepy
```

```python
from mifarepy import MifareReader

KEY = bytes.fromhex('FFFFFFFFFFFF')   # factory default key

with MifareReader('/dev/ttyUSB0') as reader:
    print('Reader:', reader.get_version())
    print('Card UID:', reader.get_uid())          # e.g. '0xEDCEF8C3'

    reader.authenticate_sector(1, KEY)
    print('Block 0:', reader.read_block(0))       # 32-char hex string
    reader.write_block(0, bytes(range(16)))
```

## What you can do

<div class="grid cards" markdown>

-   :material-card-search-outline:{ .lg .middle } __Detect cards__

    ---

    Read UIDs, check whether a card is present, block or `await` until one
    is tapped, and enumerate several cards at once.

    [:octicons-arrow-right-24: Card detection](usage.md#card-detection)

-   :material-key-variant:{ .lg .middle } __Authenticate__

    ---

    Unlock sectors with Key A or Key B, or re-use a key that is already
    loaded in the reader.

    [:octicons-arrow-right-24: Authentication](usage.md#authentication)

-   :material-database-edit-outline:{ .lg .middle } __Read & write__

    ---

    Single 16-byte blocks, whole sectors, or arbitrary block maps across
    several sectors with per-sector keys.

    [:octicons-arrow-right-24: Reading and writing](usage.md#reading-and-writing)

-   :material-wallet-outline:{ .lg .middle } __Value blocks__

    ---

    Stored-value counters for wallets, credits and loyalty points, with
    overflow checks.

    [:octicons-arrow-right-24: Value blocks](usage.md#value-blocks)

-   :material-lightning-bolt-outline:{ .lg .middle } __Events & async__

    ---

    Let the reader announce cards by itself, or wait for one without
    blocking your asyncio event loop.

    [:octicons-arrow-right-24: Waiting for cards](usage.md#wait-for-card-blocking-async)

-   :material-shield-check-outline:{ .lg .middle } __Typed & safe__

    ---

    Full type hints, `py.typed`, typed errors with readable NAK
    descriptions, and guards that never touch sector trailers by accident.

    [:octicons-arrow-right-24: Error handling](usage.md#error-handling)

</div>

## Supported hardware

| Reader | Interface | Notes |
|---|---|---|
| PROMAG **PCR310U** | USB (PL2303 USB-serial) | Desktop reader; appears as `/dev/ttyUSB*` or `COMx` |
| PROMAG **MF5** | RS-232 / TTL | OEM read/write module |
| PROMAG **MF10** | RS-232 / TTL | OEM read/write module |
| Other GNetPlus® devices | Serial | Anything implementing the GNetPlus MIFARE command set |

Cards: MIFARE Classic 1K and 4K. See [Hardware & setup](hardware.md) to get
connected, and the [MIFARE Classic primer](mifare-classic.md) if you are new
to sectors, keys and access bits.

## Learn more

<div class="grid cards" markdown>

-   :material-book-open-variant:{ .lg .middle } [__Usage guide__](usage.md)

    Every feature, with worked examples.

-   :material-chip:{ .lg .middle } [__GNetPlus protocol__](protocol.md)

    Frame format, CRC, command and error-code tables.

-   :material-school-outline:{ .lg .middle } [__MIFARE Classic primer__](mifare-classic.md)

    Memory layout, keys, access conditions and value blocks.

-   :material-play-box-multiple-outline:{ .lg .middle } [__Examples__](examples.md)

    Nine runnable scripts, from reading a UID to working with several cards at once.

</div>
