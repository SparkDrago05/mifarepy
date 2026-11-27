# mifarepy -- Python library for MIFARE readers that speak the GNetPlus protocol
# Copyright (C) 2025-2026 Spark Drago <https://github.com/SparkDrago05>
#
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version. See the LICENSE and COPYING files for details.
# SPDX-License-Identifier: LGPL-3.0-or-later

"""Sets of MIFARE Classic keys, key files, and per-card key diversification.

A `KeyRing` holds the keys to try: known keys for particular sectors, plus a
list of keys to try on every sector.

```python
from mifarepy.keys import KeyRing

ring = KeyRing.load('keys.json')             # or a .keys / .dic / .txt list
ring.set(1, key_a=bytes.fromhex('A0A1A2A3A4A5'))
key_type = reader.open_sector(1, ring)       # tries the sector's keys first
```

Key files:

* **Key list** (``.keys``, ``.dic``, ``.txt``, or any other name): one key
  per line as 12 hex digits; ``#`` starts a comment. This is the dictionary
  format of MIFARE Classic Tool and Proxmark3. Every key is tried on every
  sector.
* **JSON** (``.json``): ``{"keys": ["FFFFFFFFFFFF"], "sectors": {"1": {"A":
  "A0A1A2A3A4A5", "B": "B0B1B2B3B4B5"}}}``. Both parts are optional.

`diversify_key()` derives a different key for every card from one master
secret, so one cloned card does not reveal the keys of the others.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from typing import Iterable, Optional, Union

__all__ = ['DEFAULT_KEY', 'KeyRing', 'diversify_key', 'parse_key']

DEFAULT_KEY = b'\xff' * 6
"""The key of a new card: ``FFFFFFFFFFFF``."""

KeyLike = Union[bytes, str]


def parse_key(key: KeyLike) -> bytes:
    """Return *key* as 6 bytes. Accepts bytes or 12 hex digits (spaces and colons ignored).

    Raises:
        ValueError: If the key is not 6 bytes / 12 hex digits.
    """
    if isinstance(key, str):
        text = key.replace(' ', '').replace(':', '')
        if text.lower().startswith('0x'):
            text = text[2:]
        if len(text) != 12:
            raise ValueError(f'a key is 12 hex digits, got {key!r}')
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise ValueError(f'key {key!r} is not hex') from None
    if len(key) != 6:
        raise ValueError(f'a key is 6 bytes, got {len(key)}')
    return bytes(key)


class KeyRing:
    """Keys to try when opening sectors.

    Args:
        keys: Keys to try on every sector, in order. Defaults to the
            factory key ``FFFFFFFFFFFF``. Pass ``[]`` for none.
        sectors: Known keys per sector, as ``{sector: {'A': key, 'B': key}}``.
            These are tried first for their sector.
    """

    def __init__(
        self,
        keys: Optional[Iterable[KeyLike]] = None,
        sectors: Optional[dict[int, dict[str, KeyLike]]] = None,
    ) -> None:
        self.keys: list[bytes] = []
        self.sectors: dict[int, dict[str, bytes]] = {}
        for key in (DEFAULT_KEY,) if keys is None else keys:
            self.add(key)
        for sector, pair in (sectors or {}).items():
            self.set(int(sector), key_a=pair.get('A'), key_b=pair.get('B'))

    def add(self, key: KeyLike) -> None:
        """Add a key to try on every sector (duplicates are ignored)."""
        k = parse_key(key)
        if k not in self.keys:
            self.keys.append(k)

    def set(self, sector: int, key_a: Optional[KeyLike] = None, key_b: Optional[KeyLike] = None) -> None:
        """Record the known Key A and/or Key B of *sector*."""
        if not 0 <= sector < 40:
            raise ValueError(f'sector must be 0-39, got {sector}')
        entry = self.sectors.setdefault(sector, {})
        if key_a is not None:
            entry['A'] = parse_key(key_a)
        if key_b is not None:
            entry['B'] = parse_key(key_b)

    def get(self, sector: int, key_type: str = 'A') -> Optional[bytes]:
        """The known key of *key_type* for *sector*, or None."""
        return self.sectors.get(sector, {}).get(key_type)

    def candidates(self, sector: int, key_type: Optional[str] = None) -> list[tuple[str, bytes]]:
        """``(key_type, key)`` pairs to try on *sector*, most likely first.

        Known keys for the sector come first, then every general key as Key A
        and then as Key B (or only *key_type* if given).
        """
        types = [key_type] if key_type else ['A', 'B']
        out: list[tuple[str, bytes]] = []
        for kt in types:
            known = self.get(sector, kt)
            if known is not None:
                out.append((kt, known))
        for key in self.keys:
            for kt in types:
                if (kt, key) not in out:
                    out.append((kt, key))
        return out

    def merge(self, other: KeyRing) -> KeyRing:
        """Return a new ring with the keys of both (this ring's sector keys win)."""
        ring = KeyRing(keys=[*self.keys, *other.keys])
        for src in (other, self):
            for sector, pair in src.sectors.items():
                ring.set(sector, key_a=pair.get('A'), key_b=pair.get('B'))
        return ring

    def __len__(self) -> int:
        return len(self.keys) + sum(len(p) for p in self.sectors.values())

    def __repr__(self) -> str:
        return f'KeyRing({len(self.keys)} general key(s), {len(self.sectors)} sector(s) with known keys)'

    # -- files -------------------------------------------------------------

    @classmethod
    def load(cls, path: Union[str, os.PathLike[str]]) -> KeyRing:
        """Load a key list (one hex key per line) or a JSON key file.

        Raises:
            ValueError: If a line or entry is not a valid key.
            OSError: If the file cannot be read.
        """
        name = os.fspath(path)
        with open(name, encoding='utf-8') as fh:
            text = fh.read()
        if name.lower().endswith('.json'):
            return cls.from_json(text)
        keys = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            try:
                keys.append(parse_key(line))
            except ValueError as exc:
                raise ValueError(f'{name}, line {n}: {exc}') from None
        return cls(keys=keys)

    @classmethod
    def from_json(cls, text: str) -> KeyRing:
        """Parse the JSON key-file format."""
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError('a JSON key file is an object with "keys" and/or "sectors"')
        return cls(keys=doc.get('keys', []), sectors={int(s): p for s, p in doc.get('sectors', {}).items()})

    def to_json(self) -> str:
        """Serialise in the JSON key-file format."""
        return json.dumps({
            'keys': [k.hex().upper() for k in self.keys],
            'sectors': {str(s): {t: k.hex().upper() for t, k in sorted(p.items())}
                        for s, p in sorted(self.sectors.items())},
        }, indent=2)

    def save(self, path: Union[str, os.PathLike[str]]) -> None:
        """Save as JSON (``.json``) or as a key list (any other name; sector keys are added to the list)."""
        name = os.fspath(path)
        if name.lower().endswith('.json'):
            text = self.to_json() + '\n'
        else:
            keys = list(self.keys)
            for pair in self.sectors.values():
                keys += [k for k in pair.values() if k not in keys]
            text = ''.join(k.hex().upper() + '\n' for k in keys)
        with open(name, 'w', encoding='utf-8') as fh:
            fh.write(text)


def _uid_bytes(uid: Union[str, bytes, int]) -> bytes:
    if isinstance(uid, int):
        return struct.pack('<L', uid)
    if isinstance(uid, str):
        return struct.pack('<L', int(uid, 16))   # '0xD39BC634' as returned by get_uid()
    if len(uid) not in (4, 7, 10):
        raise ValueError('uid must be 4, 7 or 10 bytes')
    return bytes(uid)


def diversify_key(
    master: bytes,
    uid: Union[str, bytes, int],
    sector: int = 0,
    key_type: str = 'A',
) -> bytes:
    """Derive a 6-byte key for one card and sector from a master secret.

    The key is the first 6 bytes of HMAC-SHA256(master, label + UID + sector +
    key type). Every card gets different keys, so reading the keys out of one
    card does not open the others. Keep the master secret off the cards and out
    of your source code.

    This is a mifarepy pattern, not a standard: it is not NXP's AN10922
    diversification, and other tools will not derive the same keys.

    ```python
    master = bytes.fromhex(os.environ['MIFARE_MASTER_KEY'])   # 16+ random bytes
    uid = reader.get_uid()
    key_a = diversify_key(master, uid, sector=1, key_type='A')
    key_b = diversify_key(master, uid, sector=1, key_type='B')
    ```

    Args:
        master: Master secret, at least 16 bytes (``os.urandom(16)`` makes one).
        uid: The card UID: a ``'0xAABBCCDD'`` string from `MifareReader.get_uid()`,
            an int from `get_uid_int()`, or the UID bytes in card order.
        sector: Sector number, so every sector gets its own key.
        key_type: ``'A'`` or ``'B'``.

    Raises:
        ValueError: If the master secret is shorter than 16 bytes, or the
            other arguments are invalid.
    """
    if len(master) < 16:
        raise ValueError('master secret must be at least 16 bytes')
    if key_type not in ('A', 'B'):
        raise ValueError("key_type must be 'A' or 'B'")
    if not 0 <= sector < 40:
        raise ValueError(f'sector must be 0-39, got {sector}')
    message = b'mifarepy-diversify-v1' + _uid_bytes(uid) + bytes([sector]) + key_type.encode()
    return hmac.new(master, message, hashlib.sha256).digest()[:6]
