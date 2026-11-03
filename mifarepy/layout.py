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

"""MIFARE Classic memory-layout helpers.

MIFARE Classic 1K has 16 sectors of 4 blocks. MIFARE Classic 4K has 40
sectors: 0-31 have 4 blocks each, 32-39 have 16 blocks each. The last block
of every sector is its *sector trailer* (keys + access bits).

Block numbers passed to `MifareReader.read_block()` / `write_block()` are
relative to the authenticated sector; these helpers translate between
relative and absolute numbering and tell you which blocks hold data.

```python
from mifarepy import layout

layout.blocks_in_sector(5)      # 4
layout.blocks_in_sector(35)     # 16
layout.data_blocks(35)          # range(0, 15)
layout.trailer_block(35)        # 15  (relative)
layout.absolute_block(35, 0)    # 176
layout.sector_of(176)           # (35, 0)
```
"""

from __future__ import annotations

#: Number of sectors on each card type.
SECTORS_1K = 16
SECTORS_4K = 40

#: First sector that uses the large 16-block layout (4K cards only).
LARGE_SECTOR_START = 32

BLOCK_SIZE = 16


def _check_sector(sector: int) -> None:
    if not 0 <= sector < SECTORS_4K:
        raise ValueError(f'sector must be 0-{SECTORS_4K - 1}, got {sector}')


def blocks_in_sector(sector: int) -> int:
    """Return how many blocks *sector* has (4, or 16 for 4K sectors 32-39)."""
    _check_sector(sector)
    return 16 if sector >= LARGE_SECTOR_START else 4


def trailer_block(sector: int) -> int:
    """Return the relative block number of *sector*'s trailer (3 or 15)."""
    return blocks_in_sector(sector) - 1


def data_blocks(sector: int) -> range:
    """Return the relative block numbers that hold data (excludes the trailer)."""
    return range(trailer_block(sector))


def absolute_block(sector: int, block: int) -> int:
    """Convert a relative *block* within *sector* to an absolute block number."""
    count = blocks_in_sector(sector)
    if not 0 <= block < count:
        raise ValueError(f'block must be 0-{count - 1} for sector {sector}, got {block}')
    if sector < LARGE_SECTOR_START:
        return sector * 4 + block
    return LARGE_SECTOR_START * 4 + (sector - LARGE_SECTOR_START) * 16 + block


def sector_of(absolute: int) -> tuple[int, int]:
    """Convert an absolute block number to ``(sector, relative_block)``."""
    small_blocks = LARGE_SECTOR_START * 4
    if not 0 <= absolute < small_blocks + (SECTORS_4K - LARGE_SECTOR_START) * 16:
        raise ValueError(f'absolute block out of range: {absolute}')
    if absolute < small_blocks:
        return absolute // 4, absolute % 4
    offset = absolute - small_blocks
    return LARGE_SECTOR_START + offset // 16, offset % 16


def is_trailer(sector: int, block: int) -> bool:
    """Return True if relative *block* is the trailer of *sector*."""
    return block == trailer_block(sector)
