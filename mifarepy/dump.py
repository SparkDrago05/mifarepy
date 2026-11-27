# mifarepy -- Python library for MIFARE readers that speak the GNetPlus protocol
# Copyright (C) 2025-2026 Spark Drago <https://github.com/SparkDrago05>
#
# Based on gnetplus (https://github.com/harishpillay/gnetplus)
# Copyright (C) 2013 Red Hat Inc. -- Chow Loong Jin, Harish Pillay
# (originally released under LGPL-2.1-or-later)
#
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version. See the LICENSE and COPYING files for details.
# SPDX-License-Identifier: LGPL-3.0-or-later

"""Read a whole card into a `CardDump`, save it to a file, and write it back.

```python
from mifarepy import MifareReader
from mifarepy.dump import read_card, write_card, CardDump

with MifareReader.auto() as reader:
    dump = read_card(reader)                 # tries the factory key FFFFFFFFFFFF
    dump.save('card.json')                   # or .bin / .mfd / .mct

    copy = CardDump.load('card.json')
    write_card(reader, copy)                 # data blocks only; never trailers
```

File formats, chosen by extension:

- ``.json``: mifarepy's own format, with the UID, card size, every block
  (``null`` if it could not be read) and the keys that worked.
- ``.bin`` / ``.mfd``: raw memory image (1024 or 4096 bytes), as used by
  Proxmark3 and libnfc tools. Unreadable blocks are zeros.
- ``.mct``: text format of the MIFARE Classic Tool Android app. Unreadable
  blocks are dashes.

Key A can never be read from a card. Where a sector was opened with Key A,
the dump stores that key in the trailer so the file is complete.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional, Sequence, Union

from . import layout
from .keys import KeyRing
from .protocol import GNetPlusError, QueryMessage

if TYPE_CHECKING:
    from .reader import MifareReader

DEFAULT_KEYS: tuple[bytes, ...] = (b'\xff' * 6,)
SIZES = {'1K': layout.SECTORS_1K, '4K': layout.SECTORS_4K}
FORMAT_VERSION = 1


def total_blocks(size: str) -> int:
    """Number of blocks on a ``'1K'`` (64) or ``'4K'`` (256) card."""
    last = SIZES[size] - 1
    return layout.absolute_block(last, layout.trailer_block(last)) + 1


@dataclass
class CardDump:
    """The contents of a MIFARE Classic card.

    Attributes:
        uid: UID as ``'0xAABBCCDD'`` (as `MifareReader.get_uid()` returns it).
        size: ``'1K'`` or ``'4K'``.
        blocks: One entry per absolute block: 16 bytes, or None if unread.
        keys: ``{sector: (key_a, key_b)}`` for the keys that are known; either
            key may be None.
    """

    uid: str
    size: str
    blocks: list[Optional[bytes]]
    keys: dict[int, tuple[Optional[bytes], Optional[bytes]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.size not in SIZES:
            raise ValueError("size must be '1K' or '4K'")
        if len(self.blocks) != total_blocks(self.size):
            raise ValueError(f'a {self.size} dump needs {total_blocks(self.size)} blocks, '
                             f'got {len(self.blocks)}')
        for i, b in enumerate(self.blocks):
            if b is not None and len(b) != 16:
                raise ValueError(f'block {i} must be 16 bytes')

    # -- convenience -----------------------------------------------------

    @property
    def sectors(self) -> int:
        return SIZES[self.size]

    def block(self, sector: int, block: int) -> Optional[bytes]:
        """Return relative *block* of *sector*, or None if it was not read."""
        return self.blocks[layout.absolute_block(sector, block)]

    def unread_sectors(self) -> list[int]:
        """Sectors whose blocks could not be read (no working key)."""
        return [s for s in range(self.sectors)
                if all(self.block(s, b) is None for b in range(layout.blocks_in_sector(s)))]

    # -- serialisation ---------------------------------------------------

    def to_json(self) -> str:
        """Serialise to mifarepy's JSON format."""
        doc = {
            'format': 'mifarepy-dump',
            'version': FORMAT_VERSION,
            'uid': self.uid,
            'size': self.size,
            'blocks': {str(i): (b.hex().upper() if b is not None else None)
                       for i, b in enumerate(self.blocks)},
            'keys': {str(s): {'A': a.hex().upper() if a else None, 'B': b.hex().upper() if b else None}
                     for s, (a, b) in sorted(self.keys.items())},
        }
        return json.dumps(doc, indent=2) + '\n'

    @classmethod
    def from_json(cls, text: str) -> CardDump:
        doc = json.loads(text)
        if doc.get('format') != 'mifarepy-dump':
            raise ValueError('not a mifarepy JSON dump')
        size = doc['size']
        blocks: list[Optional[bytes]] = [None] * total_blocks(size)
        for k, v in doc['blocks'].items():
            blocks[int(k)] = bytes.fromhex(v) if v else None
        keys = {int(s): (bytes.fromhex(k['A']) if k.get('A') else None,
                         bytes.fromhex(k['B']) if k.get('B') else None)
                for s, k in doc.get('keys', {}).items()}
        return cls(doc['uid'], size, blocks, keys)

    def to_bin(self) -> bytes:
        """Raw memory image; unread blocks become zeros."""
        return b''.join(b if b is not None else bytes(16) for b in self.blocks)

    @classmethod
    def from_bin(cls, data: bytes) -> CardDump:
        sizes = {total_blocks(s) * 16: s for s in SIZES}
        if len(data) not in sizes:
            raise ValueError(f'a raw dump must be 1024 or 4096 bytes, got {len(data)}')
        size = sizes[len(data)]
        blocks: list[Optional[bytes]] = [data[i:i + 16] for i in range(0, len(data), 16)]
        return cls(_uid_from_block0(blocks[0]), size, blocks, _keys_from_trailers(blocks, size))

    def to_mct(self) -> str:
        """MIFARE Classic Tool text format; unread blocks become dashes."""
        lines = []
        for s in range(self.sectors):
            lines.append(f'+Sector: {s}')
            for b in range(layout.blocks_in_sector(s)):
                data = self.block(s, b)
                lines.append(data.hex().upper() if data is not None else '-' * 32)
        return '\n'.join(lines) + '\n'

    @classmethod
    def from_mct(cls, text: str) -> CardDump:
        sectors: dict[int, list[Optional[bytes]]] = {}
        current: Optional[int] = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith('+Sector:'):
                current = int(line.split(':', 1)[1])
                sectors[current] = []
            elif current is not None:
                sectors[current].append(None if '-' in line else bytes.fromhex(line))
        size = '4K' if max(sectors, default=0) >= layout.SECTORS_1K else '1K'
        blocks: list[Optional[bytes]] = [None] * total_blocks(size)
        for s, data in sectors.items():
            for b, value in enumerate(data):
                blocks[layout.absolute_block(s, b)] = value
        uid = _uid_from_block0(blocks[0]) if blocks[0] else '0x00000000'
        return cls(uid, size, blocks, _keys_from_trailers(blocks, size))

    def save(self, path: Union[str, Path]) -> None:
        """Write the dump to *path*; the format follows the extension."""
        path = Path(path)
        fmt = _format_for(path)
        if fmt == 'json':
            path.write_text(self.to_json(), encoding='utf-8')
        elif fmt == 'mct':
            path.write_text(self.to_mct(), encoding='utf-8')
        else:
            path.write_bytes(self.to_bin())

    @classmethod
    def load(cls, path: Union[str, Path]) -> CardDump:
        """Read a dump saved by `save()` (or by Proxmark3 / MIFARE Classic Tool)."""
        path = Path(path)
        fmt = _format_for(path)
        if fmt == 'json':
            return cls.from_json(path.read_text(encoding='utf-8'))
        if fmt == 'mct':
            return cls.from_mct(path.read_text(encoding='utf-8'))
        return cls.from_bin(path.read_bytes())


def _format_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == '.json':
        return 'json'
    if ext == '.mct':
        return 'mct'
    if ext in ('.bin', '.mfd', '.dump'):
        return 'bin'
    raise ValueError(f'unknown dump format {ext!r}; use .json, .bin, .mfd or .mct')


def _uid_from_block0(block0: Optional[bytes]) -> str:
    if not block0:
        return '0x00000000'
    return f"0x{struct.unpack('<L', block0[:4])[0]:08X}"


def _keys_from_trailers(blocks: list[Optional[bytes]], size: str) -> dict[int, tuple[Optional[bytes], Optional[bytes]]]:
    keys: dict[int, tuple[Optional[bytes], Optional[bytes]]] = {}
    for s in range(SIZES[size]):
        t = blocks[layout.absolute_block(s, layout.trailer_block(s))]
        if t is not None:
            keys[s] = (t[:6] if any(t[:6]) else None, t[10:])
    return keys


# -- reading and writing cards ------------------------------------------------

def detect_size(reader: MifareReader) -> str:
    """Return ``'4K'`` or ``'1K'`` for the card on the reader.

    Uses the card's answer to REQUEST (ATQA ``02 00`` is 4K) and SELECT
    (SAK ``0x18`` is 4K). Anything else is treated as 1K.
    """
    reader._auth_sector = None
    reader.sendmsg(QueryMessage.REQUEST)
    atqa = reader.readmsg(sink_events=True).data
    sak = reader.select_card()
    if atqa[:1] == b'\x02' or sak[:1] in (b'\x18', b'\x20'):
        return '4K'
    return '1K'


ProgressCallback = Callable[[int, int, Optional[str]], None]


Keys = Union[Sequence[bytes], KeyRing]


def _ring(keys: Keys) -> KeyRing:
    if isinstance(keys, KeyRing):
        return keys
    for key in keys:
        if len(key) != 6:
            raise ValueError('keys must be 6 bytes each')
    return KeyRing(keys=list(keys))


def _open_sector(
    reader: MifareReader, sector: int, candidates: Sequence[tuple[str, bytes]],
) -> Optional[tuple[str, bytes]]:
    """Authenticate *sector* with the first ``(key_type, key)`` that works."""
    for key_type, key in candidates:
        try:
            reader.authenticate_sector(sector, key, key_type)
            return key_type, key
        except GNetPlusError:
            continue
    return None


def _with_fallback(reader: MifareReader, sector: int, opened: tuple[str, bytes],
                   candidates: Sequence[tuple[str, bytes]], action: Callable[[], bytes]) -> tuple[
                       Optional[bytes], tuple[str, bytes], Optional[GNetPlusError]]:
    """Run *action*; if the card refuses it, re-open the sector with each other key and retry.

    Returns ``(result or None, key now authenticated, first error or None)``.
    The card goes idle after a refused command, so the sector is opened again
    before each retry.
    """
    try:
        return action(), opened, None
    except GNetPlusError as exc:
        first = exc
    for cand in [c for c in candidates if c != opened]:
        if _open_sector(reader, sector, [cand]) is None:
            continue
        try:
            return action(), cand, None
        except GNetPlusError:
            continue
    _open_sector(reader, sector, [opened])
    return None, opened, first


def read_card(
    reader: MifareReader,
    keys: Keys = DEFAULT_KEYS,
    size: Optional[str] = None,
    progress: Optional[ProgressCallback] = None,
) -> CardDump:
    """Read every sector the given keys can open.

    When the access bits stop the opening key from reading a block, the
    other keys are tried for that block.

    Args:
        reader: An open reader with the card in its field.
        keys: Keys to try on each sector, as Key A and then Key B, or a
            `KeyRing` with known per-sector keys.
        size: ``'1K'`` or ``'4K'``; detected from the card when None.
        progress: Called as ``progress(sector, total_sectors, key_type_or_None)``.

    Returns:
        A `CardDump`. Sectors no key opened have None blocks; see
        `CardDump.unread_sectors()`.
    """
    ring = _ring(keys)
    size = size or detect_size(reader)
    uid = reader.get_uid()
    blocks: list[Optional[bytes]] = [None] * total_blocks(size)
    found: dict[int, tuple[Optional[bytes], Optional[bytes]]] = {}
    sectors = SIZES[size]
    for sector in range(sectors):
        candidates = ring.candidates(sector)
        opened = _open_sector(reader, sector, candidates)
        if progress:
            progress(sector, sectors, opened[0] if opened else None)
        if opened is None:
            continue
        for rel in range(layout.blocks_in_sector(sector)):
            def read(rel: int = rel) -> bytes:
                return reader.read_block(rel, raw=True)
            result, opened, _ = _with_fallback(reader, sector, opened, candidates, read)
            if result is None:
                continue
            data = result
            key_type, key = opened
            if rel == layout.trailer_block(sector):
                # Key A always reads as zeros: fill in the key that opened the
                # sector. Key B bytes are as read, unless Key B opened it.
                key_a = key if key_type == 'A' else None
                key_b = key if key_type == 'B' else data[10:]
                data = (key_a or data[:6]) + data[6:10] + key_b
                found[sector] = (key_a, key_b)
            blocks[layout.absolute_block(sector, rel)] = data
    return CardDump(uid, size, blocks, found)


def write_card(
    reader: MifareReader,
    dump: CardDump,
    keys: Keys = DEFAULT_KEYS,
    sectors: Optional[Sequence[int]] = None,
    progress: Optional[ProgressCallback] = None,
) -> list[int]:
    """Write the data blocks of *dump* to the card on the reader.

    Sector trailers (keys and access bits) and the manufacturer block are
    never written, so this cannot lock a sector or change keys. Unread
    blocks (None) are skipped.

    Args:
        reader: An open reader with the target card in its field.
        dump: What to write.
        keys: Keys to try on each sector of the *target* card (a list or a
            `KeyRing`). The keys stored in the dump are tried as well, and if
            the opening key may not write a block, the other keys are tried.
        sectors: Only write these sectors (default: all in the dump).
        progress: Called as ``progress(sector, total_sectors, key_type_or_None)``.

    Returns:
        The sectors that could not be opened with any key (not written).

    Raises:
        ValueError: A sector in *sectors* is not in the dump.
        GNetPlusError: If no key may write a block of an opened sector.
    """
    ring = _ring(keys)
    skipped = []
    targets = list(sectors) if sectors is not None else list(range(dump.sectors))
    for sector in targets:
        if not 0 <= sector < dump.sectors:
            raise ValueError(f'sector {sector} is not in the {dump.size} dump (0-{dump.sectors - 1})')
    for n, sector in enumerate(targets):
        data_blocks: list[tuple[int, bytes]] = []
        for b in layout.data_blocks(sector):
            d = dump.block(sector, b)
            if d is not None and not (sector == 0 and b == 0):
                data_blocks.append((b, d))
        if not data_blocks:
            continue
        dump_a, dump_b = dump.keys.get(sector, (None, None))
        candidates = ring.candidates(sector) + [(t, k) for t, k in (('A', dump_a), ('B', dump_b)) if k]
        opened = _open_sector(reader, sector, candidates)
        if progress:
            progress(n, len(targets), opened[0] if opened else None)
        if opened is None:
            skipped.append(sector)
            continue
        for rel, data in data_blocks:
            def write(rel: int = rel, data: bytes = data) -> bytes:
                reader.write_block(rel, data)
                return data
            result, opened, error = _with_fallback(reader, sector, opened, candidates, write)
            if error is not None and result is None:
                raise error      # no key may write this block
    return skipped
