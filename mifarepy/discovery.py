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

"""Find PROMAG / GNetPlus readers on the serial ports of this computer.

```python
from mifarepy.discovery import find_ports

for port in find_ports():
    print(port.device, port.description, 'likely reader' if port.likely_reader else '')
```

`MifareReader.auto()` uses this to open the first reader it finds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from serial.tools import list_ports

#: USB vendor/product IDs of the USB-serial bridges used in PROMAG readers.
#: The PCR310U uses a Prolific PL2303 (067B:2303); later PL2303 revisions use
#: the other product IDs.
KNOWN_USB_IDS: frozenset[tuple[int, int]] = frozenset({
    (0x067B, 0x2303),
    (0x067B, 0x23A3),
    (0x067B, 0x23B3),
    (0x067B, 0x23C3),
    (0x067B, 0x23D3),
    (0x067B, 0x23E3),
    (0x067B, 0x23F3),
})


@dataclass(frozen=True)
class PortInfo:
    """A serial port, and whether it looks like a PROMAG reader.

    Attributes:
        device: Name to pass to `MifareReader`, e.g. ``'/dev/ttyUSB0'`` or ``'COM3'``.
        description: Description reported by the operating system.
        vid: USB vendor ID, or None for non-USB ports.
        pid: USB product ID, or None for non-USB ports.
        likely_reader: True if the USB IDs match a known reader bridge.
    """

    device: str
    description: str
    vid: Optional[int]
    pid: Optional[int]
    likely_reader: bool


def find_ports(include_all: bool = False) -> list[PortInfo]:
    """List serial ports, likely readers first.

    Args:
        include_all: Also return ports that don't look like a reader.

    Returns:
        Ports sorted with likely readers first, then by device name.
    """
    ports = []
    for p in list_ports.comports():
        likely = p.vid is not None and (p.vid, p.pid) in KNOWN_USB_IDS
        if likely or include_all:
            ports.append(PortInfo(p.device, p.description or '', p.vid, p.pid, likely))
    return sorted(ports, key=lambda p: (not p.likely_reader, p.device))
