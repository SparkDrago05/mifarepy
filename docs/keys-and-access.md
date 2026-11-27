# Keys and access bits

A new MIFARE Classic card opens with the key everyone knows, `FFFFFFFFFFFF`,
and lets that key read and write everything. Before you hand out cards, give
each sector its own keys and decide which key may do what. This page shows how
to do that without locking a sector by mistake.

If keys, sectors and trailers are new to you, read the
[MIFARE Classic primer](mifare-classic.md) first.

## See what a card allows

```text
$ mifarepy access 1
Sector 1 (Key A), access bits FF078069
  Block 0 (000, open): read: A, write: A, increment: A, decrement: A
  Block 1 (000, open): read: A, write: A, increment: A, decrement: A
  Block 2 (000, open): read: A, write: A, increment: A, decrement: A
  Trailer (001, transport): change Key A: A, read access bits: A, change access bits: A, read Key B: A, change Key B: A
  Key B is readable, so it is stored as data and gives no access.
```

`--decode` explains access bytes without a reader, for example ones copied
from a dump:

```text
$ mifarepy access --decode 78778869
Access bits 78778869
  Block 0 (100, write-b): read: A or B, write: B
  ...
  Trailer (011, key-b): change Key A: B, read access bits: A or B, change access bits: B, read Key B: never, change Key B: B
```

In Python:

```python
reader.authenticate_sector(1, bytes.fromhex('FFFFFFFFFFFF'))
bits = reader.read_access()
print(bits.describe())
bits.allows('write', 'A', group=0)      # True on a new card
```

## Presets

Each data block (or group of five blocks in 4K sectors 32-39) and the trailer
get a 3-bit condition. mifarepy names the useful ones.

### Data blocks

| Preset | Bits | Read | Write | Increment | Decrement, transfer, restore | Use it for |
|---|---|---|---|---|---|---|
| `open` | 000 | A or B | A or B | A or B | A or B | a new card |
| `read-only` | 010 | A or B | never | never | never | data that never changes |
| `write-b` | 100 | A or B | B | never | never | data your back office updates |
| `value` | 110 | A or B | B | B | A or B | a balance: top up with B, spend with A |
| `value-decrement` | 001 | A or B | never | never | A or B | prepaid credit that can only go down |
| `key-b` | 011 | B | B | never | never | data only the back office sees |
| `read-b` | 101 | B | never | never | never | read-only, back office only |
| `locked` | 111 | never | never | never | never | nothing, ever |

### Trailer

| Preset | Bits | Change Key A | Change access bits | Read Key B | Change Key B |
|---|---|---|---|---|---|
| `transport` | 001 | A | A | A | A |
| `key-b` | 011 | B | B | never | B |
| `fixed-keys` | 101 | never | B | never | never |
| `a-keys` | 000 | A | never | A | A |
| `frozen` | 100 | B | never | never | B |
| `read-only` | 010 | never | never | A | never |
| `permanent` | 111 | never | never | never | never |

`key-b` is the usual choice for cards you deploy: readers in the field hold
Key A and can only read; your back office holds Key B and manages the card.

When Key B is readable (`transport`, `a-keys`, `read-only`), the card treats
those six bytes as data and Key B opens nothing.

## Change keys and access bits

```python
from mifarepy import MifareReader
from mifarepy.access import AccessBits

FACTORY = bytes.fromhex('FFFFFFFFFFFF')
KEY_A = bytes.fromhex('...')   # load your keys from a safe place, not from source code
KEY_B = bytes.fromhex('...')

with MifareReader.auto() as reader:
    reader.authenticate_sector(1, FACTORY)
    reader.write_trailer(KEY_A, KEY_B, AccessBits.build(data='value', trailer='key-b'))
```

`write_trailer()` checks the new trailer, writes it, then authenticates again
with the new key and reads the access bits back to make sure they took.

To put a sector back the way it came from the factory (with `key-b`, only
Key B may do this):

```python
reader.authenticate_sector(1, KEY_B, 'B')
reader.write_trailer(FACTORY, FACTORY, AccessBits.build())
```

!!! danger "Save the keys before you write them"
    A sector whose keys are lost cannot be opened again, by anyone. Store new
    keys before calling `write_trailer()`, and try your settings on a spare
    card first.

### What the guard refuses

mifarepy checks every trailer it writes, through `write_trailer()` and through
`write_block()` on a trailer block:

* **Invalid access bits** are always refused. The access bytes hold every bit
  twice, once inverted; if the copies don't match, the card blocks the whole
  sector permanently.
* **Access bits that can never change again** (trailer conditions `000`,
  `010`, `100`, `110`, `111`) are refused unless you pass
  `allow_permanent=True`.

```python
from mifarepy.access import build_trailer, UnsafeTrailerError

build_trailer(KEY_A, KEY_B, trailer='frozen')                        # raises UnsafeTrailerError
build_trailer(KEY_A, KEY_B, trailer='frozen', allow_permanent=True)  # 16 bytes, your call
```

The `mifarepy write` command never writes trailers.

## Key sets and key files

A `KeyRing` holds the keys to try: known keys for particular sectors, and a
list of keys to try on every sector.

```python
from mifarepy import KeyRing

ring = KeyRing.load('keys.json')
key_type, key = reader.open_sector(4, ring)   # the sector's own keys are tried first
```

Two file formats:

* **Key list** (`.keys`, `.dic`, `.txt`): one key per line as 12 hex digits,
  `#` starts a comment. MIFARE Classic Tool and Proxmark3 use this format.
* **JSON**, with per-sector keys:

    ```json
    {
      "keys": ["FFFFFFFFFFFF"],
      "sectors": {"1": {"A": "A0A1A2A3A4A5", "B": "B0B1B2B3B4B5"}}
    }
    ```

Every command that opens sectors takes `--keys FILE` (repeat it for several
files):

```bash
mifarepy read --keys keys.json
mifarepy dump card.json --keys mykeys.dic --keys keys.json
```

`read`, `dump` and `restore` use the right key for each block: if the key that
opened a sector may not read or write one of its blocks, the other keys are
tried for that block.

### Keys stored in the reader

The reader keeps one key per sector and key type. `store_keys()` saves a
ring's keys there, so `authenticate_sector_cached()` can skip sending the key
each time:

```python
reader.store_keys(ring, sectors=16)
reader.authenticate_sector_cached(4, 'B')
```

## One key per card

If every card shares the same keys, reading them out of one card opens all
the others. `diversify_key()` derives different keys for each card from one
master secret:

```python
import os
from mifarepy.keys import diversify_key

master = bytes.fromhex(os.environ['MIFARE_MASTER_KEY'])   # 16+ random bytes, kept off the cards
uid = reader.get_uid()
key_a = diversify_key(master, uid, sector=1, key_type='A')
key_b = diversify_key(master, uid, sector=1, key_type='B')
```

The key is the first 6 bytes of HMAC-SHA256 over the UID, sector and key type.
This is a mifarepy pattern, not a standard: it is not NXP's AN10922
diversification, and other tools won't derive the same keys.

!!! note "MIFARE Classic is not strong cryptography"
    The Crypto-1 cipher of MIFARE Classic is broken: with the right tools,
    keys can be recovered from a card. Per-card keys limit the damage to one
    card. For high-value uses, keep the real balance on your server and treat
    the card as an identifier.

## Card type

```python
reader.card_type()     # '1K', '4K', 'Ultralight' or 'unknown'
```

It uses the card's answer to REQUEST and SELECT (ATQA and SAK). `mifarepy
info` shows it too.

## In the simulator

The [simulated card](testing.md) enforces access bits the way a card does, so
you can test these settings without a reader:

```python
from mifarepy import MifareReader, CardWriteError
from mifarepy.access import AccessBits
from mifarepy.simulator import SimulatedCard

card = SimulatedCard()
card.set_trailer(1, KEY_A, KEY_B, AccessBits.build('read-only', 'key-b'))
reader = MifareReader.simulated(card)
reader.authenticate_sector(1, KEY_A)
reader.read_block(0)                 # fine
reader.write_block(0, bytes(16))     # raises CardWriteError: the block is read-only
```

A refused command raises `CardReadError`, `CardWriteError` or
`ValueBlockError`, and the card drops to idle, so authenticate again before
the next command.
