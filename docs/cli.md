# Command line

Installing mifarepy also installs the `mifarepy` command. It finds the reader
for you, so most commands need no options at all.

```text
$ mifarepy info
Reader:   /dev/ttyUSB0
Firmware: PGM0487 V1.4R0 (Build:110609)
Card:     0xD39BC634 (MIFARE Classic 1K)
```

Every command also runs with `python -m mifarepy`.

!!! tip "No reader? Add `--simulate`"
    Every command accepts `--simulate`, which uses the built-in simulated
    reader with a demo card in it. It's the quickest way to try the commands.

## Commands

| Command | What it does |
|---|---|
| [`info`](#info) | Show the reader, its firmware and the card on it |
| [`scan`](#scan) | Print the UID of the card on the reader |
| [`watch`](#watch) | Print each card as it is tapped |
| [`read`](#read) | Show the blocks of one or more sectors |
| [`write`](#write) | Write one data block |
| [`dump`](#dump) | Save the whole card to a file |
| [`restore`](#restore) | Write a saved dump's data blocks to a card |

### Options for every command

| Option | Meaning |
|---|---|
| `--port PORT` | Use this serial port (e.g. `/dev/ttyUSB0`, `COM3`). By default the reader is [found automatically](hardware.md#find-the-reader-automatically). |
| `--simulate` | Use the simulated reader instead of hardware |
| `--json` | Print JSON lines instead of text, for scripts |
| `--trace` | Print every frame sent and received, with keys hidden ([frame tracing](usage.md#frame-tracing)) |

Commands that open sectors (`read`, `write`, `dump`, `restore`) also take:

| Option | Meaning |
|---|---|
| `--key HEX` | Key to try, 12 hex digits. Repeat to try several. Default `FFFFFFFFFFFF`. |
| `--key-type A\|B` | Only try this key type. By default each key is tried as Key A, then Key B. |

## info

```text
$ mifarepy info
Reader:   /dev/ttyUSB0
Firmware: PGM0487 V1.4R0 (Build:110609)
Card:     0xD39BC634 (MIFARE Classic 1K)
```

## scan

Prints the UID and exits. Exit code 1 means there was no card.

```text
$ mifarepy scan
0xD39BC634

$ mifarepy scan --wait 10      # wait up to 10 seconds for a card
$ mifarepy scan --json
{"uid": "0xD39BC634"}
```

## watch

Prints a line each time a card is placed on the reader, until you press
++ctrl+c++. Leaving a card on the reader doesn't repeat it.

```text
$ mifarepy watch
Waiting for cards (Ctrl+C to stop)...
2026-11-25T12:30:01  0xD39BC634
2026-11-25T12:30:07  0x5E1A2B3C
```

`--json` prints one JSON object per card (`{"time": ..., "uid": ...}`),
which is handy to pipe into another program. `--count N` stops after N cards.

## read

Shows the blocks of the sectors you name, or of every sector.

```text
$ mifarepy read 1
Sector 1 (Key A)
   0  48656C6C6F2C206D6966617265707921  Hello, mifarepy!
   1  00000000000000000000000000000000  ................
   2  00000000000000000000000000000000  ................
   3  000000000000FF078069FFFFFFFFFFFF  (trailer: Key A | access bits | Key B)

$ mifarepy read 1 2 --key A0A1A2A3A4A5     # sectors 1 and 2 with your key
$ mifarepy read 1 --block 0 --json
```

Key A always reads as zeros: cards never reveal it.

## write

Writes 16 bytes to one data block, then reads it back to verify.

```text
$ mifarepy write 1 1 --text "Badge 0042"
Write 42616467652030303432000000000000 to sector 1, block 1 of card 0xD39BC634? [y/N] y
Wrote and verified sector 1, block 1.

$ mifarepy write 1 2 00112233445566778899AABBCCDDEEFF --yes
```

`--text` writes up to 16 bytes of text, padded with zeros. `--yes` skips the
question (needed in scripts).

!!! success "Safe by design"
    `write` refuses sector trailers (keys and access bits, where a mistake can
    lock a sector for good) and the read-only manufacturer block.

## dump

Reads the whole card and saves it. The file type follows the extension:

| Extension | Format |
|---|---|
| `.json` | mifarepy's format: UID, size, every block, and the keys that worked |
| `.bin`, `.mfd` | Raw memory image (1024 or 4096 bytes), as used by Proxmark3 and libnfc tools |
| `.mct` | Text format of the MIFARE Classic Tool Android app |

```text
$ mifarepy dump card.json
  reading sector 1/16: Key A
  ...
  reading sector 16/16: Key A
Saved 1K card 0xD39BC634 to card.json

$ mifarepy dump card.mfd --key A0A1A2A3A4A5 --key FFFFFFFFFFFF
```

Pass every key you use with `--key`. If no key opens a sector, the dump says
so, leaves that sector empty and exits with code 3. Since Key A can't be read
from a card, the dump stores the key that opened the sector in its trailer.

## restore

Writes the data blocks of a dump to the card on the reader, for example to
copy one card's contents to another.

```text
$ mifarepy restore card.json
Write the data blocks of card.json to card 0x5E1A2B3C (the dump is from 0xD39BC634)?
Trailers and the manufacturer block are not written. [y/N] y
Restored card.json to 0x5E1A2B3C.

$ mifarepy restore card.json --sector 1 --sector 2 --yes
```

Sector trailers and the manufacturer block are never written, so `restore`
cannot change keys or lock a sector. The UID is not copied: it's fixed at the
factory. Keys are tried from `--key` and from the dump itself.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (no reader, no card, wrong key, refused write, …). The message says why. |
| 2 | Invalid command or options |
| 3 | Partly done: `dump` or `restore` could not open some sectors |
| 130 | Interrupted with ++ctrl+c++ |

## From Python

`dump` and `restore` are built on `mifarepy.dump`, which you can use directly:

```python
from mifarepy import MifareReader
from mifarepy.dump import CardDump, read_card, write_card

with MifareReader.auto() as reader:
    dump = read_card(reader, keys=[bytes.fromhex('FFFFFFFFFFFF')])
    dump.save('card.json')

    write_card(reader, CardDump.load('card.json'))
```
