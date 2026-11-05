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

"""Wire-level tracing of GNetPlus frames.

Every frame `MifareReader` sends or receives is logged on the
``mifarepy.wire`` logger at DEBUG level, decoded and with card keys hidden:

```text
TX SAVE_KEY        01 00 2B 08 | 60 01 ** ** ** ** ** ** | 3A 9C
RX ACK             01 00 06 00 | | 51 B0
TX READ_BLOCK      01 00 24 01 | 04 | 02 C8
RX NAK 0x0A        01 00 15 01 | 0A | 6E 3D   Not authenticated
```

Turn it on with `enable_wire_trace()`, or attach your own handler to the
``mifarepy.wire`` logger.
"""

from __future__ import annotations

import logging
import sys
from typing import IO, Optional

from .protocol import _NAK_CODES, QueryMessage, ResponseMessage

wire_logger = logging.getLogger('mifarepy.wire')

#: Function code -> command name, for the host-to-reader direction.
COMMAND_NAMES: dict[int, str] = {
    value: name for name, value in vars(QueryMessage).items()
    if name.isupper() and isinstance(value, int)
}
_RESPONSE_NAMES = {ResponseMessage.ACK: 'ACK', ResponseMessage.NAK: 'NAK', ResponseMessage.EVN: 'EVN'}

#: Byte ranges of each query's payload that hold key material.
_KEY_RANGES: dict[int, tuple[slice, ...]] = {
    QueryMessage.SAVE_KEY: (slice(2, 8),),
    QueryMessage.AUTHENTICATE_KEY: (slice(2, 8),),
    QueryMessage.ACCESS_CONDITION: (slice(0, 6), slice(-6, None)),
}

_show_keys = False


def _hex(data: bytes) -> str:
    return ' '.join(f'{b:02X}' for b in data)


def _redact(function: int, payload: bytes) -> str:
    ranges = _KEY_RANGES.get(function)
    if _show_keys or not ranges:
        return _hex(payload)
    hidden = [False] * len(payload)
    for r in ranges:
        for i in range(len(payload))[r]:
            hidden[i] = True
    return ' '.join('**' if h else f'{b:02X}' for b, h in zip(payload, hidden))


def format_frame(direction: str, frame: bytes) -> str:
    """Return a one-line, human-readable description of a raw frame.

    Args:
        direction: ``'TX'`` (host to reader) or ``'RX'`` (reader to host).
        frame: The complete frame bytes, starting with SOH.
    """
    if len(frame) < 4:
        return f'{direction} (short frame) {_hex(frame)}'
    function, length = frame[2], frame[3]
    payload, crc = frame[4:4 + length], frame[4 + length:]
    if direction == 'TX':
        name = COMMAND_NAMES.get(function, f'0x{function:02X}')
        body = _redact(function, payload)
        note = ''
    else:
        name = _RESPONSE_NAMES.get(function, f'0x{function:02X}')
        body = _hex(payload)
        note = ''
        if function == ResponseMessage.NAK and len(payload) == 1:
            name = f'NAK 0x{payload[0]:02X}'
            note = '   ' + _NAK_CODES.get(payload, 'Unknown error')
        elif function == ResponseMessage.EVN:
            note = f'   {payload!r}'
    return f'{direction} {name:<16} {_hex(frame[:4])} | {body} | {_hex(crc)}{note}'


def log_frame(direction: str, frame: bytes) -> None:
    """Log *frame* on the ``mifarepy.wire`` logger (cheap when tracing is off)."""
    if wire_logger.isEnabledFor(logging.DEBUG):
        wire_logger.debug(format_frame(direction, frame))


def enable_wire_trace(
    stream: Optional[IO[str]] = None,
    show_keys: bool = False,
) -> logging.Handler:
    """Print every frame to *stream* (default: stderr).

    Args:
        stream: Where to write the trace.
        show_keys: Also print key bytes instead of ``**``. Only use this on
            test cards: the output then contains secrets.

    Returns:
        The handler that was added; pass it to `disable_wire_trace()` to stop.
    """
    global _show_keys
    _show_keys = show_keys
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(message)s', '%H:%M:%S'))
    wire_logger.addHandler(handler)
    wire_logger.setLevel(logging.DEBUG)
    return handler


def disable_wire_trace(handler: Optional[logging.Handler] = None) -> None:
    """Stop tracing that was started with `enable_wire_trace()`."""
    global _show_keys
    _show_keys = False
    if handler is not None:
        wire_logger.removeHandler(handler)
    if not wire_logger.handlers:
        wire_logger.setLevel(logging.NOTSET)
