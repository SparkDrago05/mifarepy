# mifarepy -- Python library for MIFARE readers that speak the GNetPlus protocol
# Copyright (C) 2025-2026 Spark Drago <https://github.com/SparkDrago05>
#
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version. See the LICENSE and COPYING files for details.
# SPDX-License-Identifier: LGPL-3.0-or-later

"""Access bits of MIFARE Classic sector trailers: build, decode and check them.

Every sector ends with a trailer block: Key A (6 bytes), the access bits
(3 bytes), a general-purpose byte, and Key B (6 bytes). The access bits decide
which key may read, write or change each block. A wrong trailer can lock a
sector for good, so this module builds trailers from named presets and refuses
ones that would be invalid or permanent unless you ask for them.

```python
from mifarepy.access import AccessBits, build_trailer, decode_trailer

trailer = build_trailer(key_a, key_b, data='write-b', trailer='key-b')
print(decode_trailer(trailer).describe())
```

Each block has a 3-bit condition ``C1 C2 C3``, written here as a string such
as ``'000'``. Data-block presets:

| Preset | Bits | Read | Write | Increment | Decrement, transfer, restore |
|---|---|---|---|---|---|
| ``open`` | 000 | A or B | A or B | A or B | A or B |
| ``read-only`` | 010 | A or B | never | never | never |
| ``write-b`` | 100 | A or B | B | never | never |
| ``value`` | 110 | A or B | B | B | A or B |
| ``value-decrement`` | 001 | A or B | never | never | A or B |
| ``key-b`` | 011 | B | B | never | never |
| ``read-b`` | 101 | B | never | never | never |
| ``locked`` | 111 | never | never | never | never |

Trailer presets (what each key may do to the trailer itself):

| Preset | Bits | Change Key A | Read access bits | Change access bits | Read Key B | Change Key B |
|---|---|---|---|---|---|---|
| ``transport`` | 001 | A | A | A | A | A |
| ``key-b`` | 011 | B | A or B | B | never | B |
| ``fixed-keys`` | 101 | never | A or B | B | never | never |
| ``a-keys`` | 000 | A | A | never | A | A |
| ``frozen`` | 100 | B | A or B | never | never | B |
| ``read-only`` | 010 | never | A | never | A | never |
| ``permanent`` | 110 or 111 | never | A or B | never | never | never |

``transport`` is how new cards ship. ``key-b`` is the usual choice for a
deployed card: Key A reads, Key B manages. Presets where the access bits
can never be changed again (``000``, ``010``, ``100``, ``110``, ``111``) are
refused unless you pass ``allow_permanent=True``.

When Key B is readable (trailer conditions ``000``, ``010`` and ``001``), the
card treats Key B as plain data: authenticating with it gives no access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Union

__all__ = [
    'AccessBits',
    'DATA_PRESETS',
    'TRAILER_PRESETS',
    'TRANSPORT_ACCESS',
    'UnsafeTrailerError',
    'build_trailer',
    'check_trailer',
    'decode_trailer',
]

TRANSPORT_ACCESS = bytes.fromhex('FF078069')
"""Access bits and general-purpose byte of a new card (``FF 07 80 69``)."""

DATA_PRESETS = {
    'open': '000',
    'read-only': '010',
    'write-b': '100',
    'value': '110',
    'value-decrement': '001',
    'key-b': '011',
    'read-b': '101',
    'locked': '111',
}
"""Named conditions for data blocks."""

TRAILER_PRESETS = {
    'transport': '001',
    'key-b': '011',
    'fixed-keys': '101',
    'a-keys': '000',
    'frozen': '100',
    'read-only': '010',
    'permanent': '111',
}
"""Named conditions for the sector trailer."""

# Trailer conditions after which the access bits can never change again.
PERMANENT_TRAILER_CONDITIONS = frozenset({'000', '010', '100', '110', '111'})
# Trailer conditions in which Key B is readable (and so not usable as a key).
KEY_B_READABLE = frozenset({'000', '010', '001'})

_A, _B, _AB, _NEVER = 'A', 'B', 'A or B', 'never'

# Data block: (read, write, increment, decrement/transfer/restore)
_DATA_RIGHTS = {
    '000': (_AB, _AB, _AB, _AB),
    '010': (_AB, _NEVER, _NEVER, _NEVER),
    '100': (_AB, _B, _NEVER, _NEVER),
    '110': (_AB, _B, _B, _AB),
    '001': (_AB, _NEVER, _NEVER, _AB),
    '011': (_B, _B, _NEVER, _NEVER),
    '101': (_B, _NEVER, _NEVER, _NEVER),
    '111': (_NEVER, _NEVER, _NEVER, _NEVER),
}

# Trailer: (write Key A, read access bits, write access bits, read Key B, write Key B)
_TRAILER_RIGHTS = {
    '000': (_A, _A, _NEVER, _A, _A),
    '010': (_NEVER, _A, _NEVER, _A, _NEVER),
    '100': (_B, _AB, _NEVER, _NEVER, _B),
    '110': (_NEVER, _AB, _NEVER, _NEVER, _NEVER),
    '001': (_A, _A, _A, _A, _A),
    '011': (_B, _AB, _B, _NEVER, _B),
    '101': (_NEVER, _AB, _B, _NEVER, _NEVER),
    '111': (_NEVER, _AB, _NEVER, _NEVER, _NEVER),
}

DATA_OPERATIONS = ('read', 'write', 'increment', 'decrement')
TRAILER_OPERATIONS = ('write_key_a', 'read_access', 'write_access', 'read_key_b', 'write_key_b')


class UnsafeTrailerError(ValueError):
    """A sector trailer that would lock the sector, now or for good.

    Raised for access bits whose inverted copies do not match (the card would
    block the whole sector permanently), and for trailer conditions after
    which the access bits can never be changed, unless
    ``allow_permanent=True`` was passed.
    """


def _condition(value: Union[str, int, Sequence[int]], presets: dict[str, str], what: str) -> str:
    if isinstance(value, str):
        if value in presets:
            return presets[value]
        if len(value) == 3 and set(value) <= {'0', '1'}:
            return value
        names = ', '.join(presets)
        raise ValueError(f'unknown {what} condition {value!r}: use one of {names}, or bits like "011"')
    if isinstance(value, int):
        if not 0 <= value <= 7:
            raise ValueError(f'{what} condition must be 0-7, got {value}')
        return format(value, '03b')
    bits = list(value)
    if len(bits) != 3 or any(b not in (0, 1) for b in bits):
        raise ValueError(f'{what} condition must be three bits (C1, C2, C3), got {value!r}')
    return ''.join(str(b) for b in bits)


def _allowed(rule: str, key_type: str) -> bool:
    return rule == _AB or rule == key_type


@dataclass(frozen=True)
class AccessBits:
    """Decoded access conditions of one sector.

    Attributes:
        data: Conditions of the three data-block groups, as bit strings
            (``C1 C2 C3``). On 1K cards and the small sectors of 4K cards each
            group is one block; in 4K sectors 32-39 each group covers five
            blocks (0-4, 5-9, 10-14).
        trailer: Condition of the sector trailer.
        gpb: The general-purpose byte (byte 9 of the trailer). The card does
            not use it.
    """

    data: tuple[str, str, str] = ('000', '000', '000')
    trailer: str = '001'
    gpb: int = 0x69

    @classmethod
    def build(
        cls,
        data: Union[str, int, Sequence[Union[str, int]]] = 'open',
        trailer: Union[str, int] = 'transport',
        gpb: int = 0x69,
    ) -> AccessBits:
        """Make access conditions from preset names or bit strings.

        Args:
            data: One condition for all data blocks, or a list of three (one
                per block or block group). Each is a preset name from
                `DATA_PRESETS`, a bit string like ``'110'``, or an int 0-7.
            trailer: Trailer condition: a preset name from `TRAILER_PRESETS`,
                a bit string or an int 0-7.
            gpb: General-purpose byte (0-255).
        """
        if isinstance(data, (str, int)):
            groups = [data, data, data]
        else:
            groups = list(data)
            if len(groups) != 3:
                raise ValueError('data takes one condition, or a list of three (one per block group)')
        conds = tuple(_condition(g, DATA_PRESETS, 'data') for g in groups)
        if not 0 <= gpb <= 255:
            raise ValueError('gpb must be 0-255')
        return cls((conds[0], conds[1], conds[2]), _condition(trailer, TRAILER_PRESETS, 'trailer'), gpb)

    @classmethod
    def from_bytes(cls, access: bytes) -> AccessBits:
        """Decode the 4 access bytes (trailer bytes 6-9), or a whole 16-byte trailer.

        Raises:
            UnsafeTrailerError: If the inverted copies of the bits do not
                match. A card with such a trailer blocks the sector.
        """
        if len(access) == 16:
            access = access[6:10]
        if len(access) not in (3, 4):
            raise ValueError('give the 4 access bytes (trailer bytes 6-9) or a 16-byte trailer')
        b6, b7, b8 = access[0], access[1], access[2]
        c1 = b7 >> 4
        c2 = b8 & 0x0F
        c3 = b8 >> 4
        if (b6 & 0x0F) != (~c1 & 0x0F) or (b6 >> 4) != (~c2 & 0x0F) or (b7 & 0x0F) != (~c3 & 0x0F):
            raise UnsafeTrailerError(
                f'access bytes {access[:3].hex().upper()} are invalid: their inverted copies do not '
                'match. A card with these bits blocks the whole sector permanently.')
        conds = [f'{(c1 >> i) & 1}{(c2 >> i) & 1}{(c3 >> i) & 1}' for i in range(4)]
        gpb = access[3] if len(access) == 4 else 0x69
        return cls((conds[0], conds[1], conds[2]), conds[3], gpb)

    def to_bytes(self) -> bytes:
        """Encode as the 4 trailer bytes 6-9 (access bits and general-purpose byte)."""
        c1 = c2 = c3 = 0
        for i, cond in enumerate((*self.data, self.trailer)):
            c1 |= int(cond[0]) << i
            c2 |= int(cond[1]) << i
            c3 |= int(cond[2]) << i
        b6 = ((~c2 & 0x0F) << 4) | (~c1 & 0x0F)
        b7 = (c1 << 4) | (~c3 & 0x0F)
        b8 = (c3 << 4) | c2
        return bytes([b6, b7, b8, self.gpb])

    # -- questions -------------------------------------------------------------

    @property
    def is_permanent(self) -> bool:
        """True if these access bits can never be changed once written."""
        return self.trailer in PERMANENT_TRAILER_CONDITIONS

    @property
    def key_b_readable(self) -> bool:
        """True if Key B can be read, which also means it gives no access."""
        return self.trailer in KEY_B_READABLE

    def data_rights(self, group: int) -> dict[str, str]:
        """Who may read, write, increment and decrement data group *group* (0-2).

        Values are ``'A'``, ``'B'``, ``'A or B'`` or ``'never'``. Key B counts
        as ``'never'`` when it is readable.
        """
        rights = dict(zip(DATA_OPERATIONS, _DATA_RIGHTS[self.data[group]]))
        if self.key_b_readable:
            rights = {op: (_A if r == _AB else _NEVER if r == _B else r) for op, r in rights.items()}
        return rights

    def trailer_rights(self) -> dict[str, str]:
        """Who may change Key A, read and change the access bits, and read and change Key B."""
        return dict(zip(TRAILER_OPERATIONS, _TRAILER_RIGHTS[self.trailer]))

    def allows(self, operation: str, key_type: str, group: Optional[int] = None) -> bool:
        """Whether *key_type* (``'A'`` or ``'B'``) may do *operation*.

        Args:
            operation: One of ``read``, ``write``, ``increment``, ``decrement``
                (with *group*), or one of the trailer operations
                ``write_key_a``, ``read_access``, ``write_access``,
                ``read_key_b``, ``write_key_b`` (without *group*).
            key_type: ``'A'`` or ``'B'``.
            group: Data-block group 0-2 for data operations.
        """
        if key_type == 'B' and self.key_b_readable:
            return False
        if group is not None:
            return _allowed(dict(zip(DATA_OPERATIONS, _DATA_RIGHTS[self.data[group]]))[operation], key_type)
        return _allowed(self.trailer_rights()[operation], key_type)

    def describe(self, blocks_per_group: int = 1) -> str:
        """Explain the conditions in plain language, one line per block group.

        Args:
            blocks_per_group: 1 for 1K cards and 4K sectors 0-31; 5 for 4K
                sectors 32-39.
        """
        lines = []
        for g in range(3):
            if blocks_per_group == 1:
                label = f'Block {g}'
            else:
                first = g * blocks_per_group
                label = f'Blocks {first}-{first + blocks_per_group - 1}'
            r = self.data_rights(g)
            name = _preset_name(self.data[g], DATA_PRESETS)
            parts = [f'read: {r["read"]}', f'write: {r["write"]}']
            if r['increment'] != _NEVER or r['decrement'] != _NEVER:
                parts += [f'increment: {r["increment"]}', f'decrement: {r["decrement"]}']
            lines.append(f'{label} ({self.data[g]}{name}): ' + ', '.join(parts))
        t = self.trailer_rights()
        name = _preset_name(self.trailer, TRAILER_PRESETS)
        lines.append(
            f'Trailer ({self.trailer}{name}): change Key A: {t["write_key_a"]}, '
            f'read access bits: {t["read_access"]}, change access bits: {t["write_access"]}, '
            f'read Key B: {t["read_key_b"]}, change Key B: {t["write_key_b"]}')
        if self.key_b_readable:
            lines.append('Key B is readable, so it is stored as data and gives no access.')
        if self.is_permanent:
            lines.append('These access bits can never be changed again.')
        return '\n'.join(lines)

    def __str__(self) -> str:
        return self.to_bytes().hex().upper()


def _preset_name(cond: str, presets: dict[str, str]) -> str:
    names = [n for n, c in presets.items() if c == cond]
    if cond == '110' and presets is TRAILER_PRESETS:
        names = ['permanent']
    return f', {names[0]}' if names else ''


def check_trailer(trailer: bytes, *, allow_permanent: bool = False) -> AccessBits:
    """Check a 16-byte trailer (or 4 access bytes) before it is written.

    Returns:
        The decoded `AccessBits`.

    Raises:
        UnsafeTrailerError: If the access bits are invalid (always), or can
            never be changed again and *allow_permanent* is False.
    """
    bits = AccessBits.from_bytes(trailer)
    if bits.is_permanent and not allow_permanent:
        raise UnsafeTrailerError(
            f'trailer condition {bits.trailer} makes the access bits permanent: they can never be '
            'changed again. Pass allow_permanent=True if that is what you want.')
    return bits


def build_trailer(
    key_a: bytes,
    key_b: bytes,
    data: Union[str, int, Sequence[Union[str, int]]] = 'open',
    trailer: Union[str, int] = 'transport',
    gpb: int = 0x69,
    *,
    allow_permanent: bool = False,
) -> bytes:
    """Build a 16-byte sector trailer: Key A, access bits, general-purpose byte, Key B.

    ```python
    # Key A can read, Key B can write and manage the sector:
    trailer = build_trailer(key_a, key_b, data='write-b', trailer='key-b')
    ```

    Args:
        key_a: 6-byte Key A.
        key_b: 6-byte Key B.
        data: Data-block condition(s): see `AccessBits.build()`.
        trailer: Trailer condition: see `AccessBits.build()`.
        gpb: General-purpose byte.
        allow_permanent: Allow trailer conditions after which the access bits
            can never be changed.

    Raises:
        ValueError: For wrong key lengths or unknown conditions.
        UnsafeTrailerError: For permanent conditions without *allow_permanent*.
    """
    if len(key_a) != 6 or len(key_b) != 6:
        raise ValueError('key_a and key_b must be 6 bytes each')
    bits = AccessBits.build(data, trailer, gpb)
    block = bytes(key_a) + bits.to_bytes() + bytes(key_b)
    check_trailer(block, allow_permanent=allow_permanent)
    return block


def decode_trailer(trailer: bytes) -> AccessBits:
    """Decode a 16-byte trailer as read from the card (or its 4 access bytes)."""
    return AccessBits.from_bytes(trailer)
