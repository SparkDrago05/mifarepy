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

"""A simulated GNetPlus reader and MIFARE Classic cards, for testing without hardware.

`SimulatedReader` behaves like the serial port of a PROMAG reader: it decodes
the GNetPlus frames `MifareReader` sends and answers the way a reader would.
`SimulatedCard` holds the memory of a MIFARE Classic 1K or 4K card.

```python
from mifarepy import MifareReader
from mifarepy.simulator import SimulatedCard

card = SimulatedCard(uid='0xD39BC634')
reader = MifareReader.simulated(card)

reader.authenticate_sector(1, bytes.fromhex('FFFFFFFFFFFF'))
reader.write_block(0, b'Hello, mifarepy!')
assert card.read(1, 0) == b'Hello, mifarepy!'
```

What is modelled: card presence, request / anti-collision / select, HALT,
RF power, keys (authentication fails with the wrong key or key type),
block reads and writes relative to the authenticated sector (Key A reads back
as zeros), value blocks (create, read, increment, decrement, restore,
transfer), auto mode with card-arrival events, polling, version and echo.

What is not modelled yet: access-condition enforcement beyond keys, and the
firmware quirks of specific reader models. Always check on real hardware
before shipping.
"""

from __future__ import annotations

import struct
import threading
from io import BytesIO
from typing import Optional, Union

from . import layout
from .protocol import InvalidMessage, Message, QueryMessage, ResponseMessage

DEFAULT_KEY = b'\xff' * 6
TRANSPORT_ACCESS = bytes.fromhex('FF078069')  # access bits + GPB of a new card
KEY_A, KEY_B = 0x60, 0x61

# NAK codes used by the simulator (vendor error-code table).
NAK_AUTH = 0x04
NAK_NOT_AUTH = 0x0A
NAK_TRANSFER = 0x0E
NAK_READ = 0x12
NAK_NO_TAG = 0x1F
NAK_PARAM = 0x27
NAK_UNKNOWN = 0xE6


class SimulatedCard:
    """Memory and state of one MIFARE Classic card.

    Args:
        uid: 4-byte UID as bytes (card order) or a ``'0xAABBCCDD'`` string as
            returned by `MifareReader.get_uid()`.
        size: ``'1K'`` (16 sectors) or ``'4K'`` (40 sectors).
        keys: Optional ``{sector: (key_a, key_b)}`` to start with non-default keys.
    """

    def __init__(
        self,
        uid: Union[bytes, str] = b'\x34\xc6\x9b\xd3',
        size: str = '1K',
        keys: Optional[dict[int, tuple[bytes, bytes]]] = None,
    ) -> None:
        if size not in ('1K', '4K'):
            raise ValueError("size must be '1K' or '4K'")
        if isinstance(uid, str):
            uid = struct.pack('<L', int(uid, 16))
        if len(uid) != 4:
            raise ValueError('uid must be 4 bytes')
        self.uid = bytes(uid)
        self.size = size
        self.sectors = layout.SECTORS_1K if size == '1K' else layout.SECTORS_4K
        total = layout.absolute_block(self.sectors - 1, layout.trailer_block(self.sectors - 1)) + 1
        self.memory = [bytearray(16) for _ in range(total)]
        bcc = self.uid[0] ^ self.uid[1] ^ self.uid[2] ^ self.uid[3]
        self.memory[0][:] = self.uid + bytes([bcc, 0x08, 0x04, 0x00]) + b'mifarepy'
        for sector in range(self.sectors):
            key_a, key_b = (keys or {}).get(sector, (DEFAULT_KEY, DEFAULT_KEY))
            self.set_trailer(sector, key_a, key_b)
        self.halted = False

    # -- helpers for tests ------------------------------------------------

    @property
    def uid_str(self) -> str:
        """The UID formatted like `MifareReader.get_uid()`, e.g. ``'0xD39BC634'``."""
        return f"0x{struct.unpack('<L', self.uid)[0]:08X}"

    def read(self, sector: int, block: int) -> bytes:
        """Return the 16 bytes of relative *block* in *sector* (no authentication)."""
        return bytes(self.memory[layout.absolute_block(sector, block)])

    def write(self, sector: int, block: int, data: bytes) -> None:
        """Set relative *block* in *sector* directly (no authentication)."""
        if len(data) != 16:
            raise ValueError('data must be 16 bytes')
        self.memory[layout.absolute_block(sector, block)][:] = data

    def set_trailer(self, sector: int, key_a: bytes = DEFAULT_KEY, key_b: bytes = DEFAULT_KEY,
                    access: bytes = TRANSPORT_ACCESS) -> None:
        """Set the keys (and optionally access bytes) of *sector*."""
        if len(key_a) != 6 or len(key_b) != 6 or len(access) != 4:
            raise ValueError('keys must be 6 bytes and access 4 bytes')
        self.write(sector, layout.trailer_block(sector), key_a + access + key_b)

    def keys(self, sector: int) -> tuple[bytes, bytes]:
        """Return ``(key_a, key_b)`` of *sector*."""
        trailer = self.read(sector, layout.trailer_block(sector))
        return trailer[:6], trailer[10:]

    def value(self, sector: int, block: int) -> Optional[int]:
        """Decode relative *block* of *sector* as a value block, or None if it isn't one."""
        return _decode_value(self.read(sector, block))

    @property
    def atqa(self) -> bytes:
        return b'\x04\x00' if self.size == '1K' else b'\x02\x00'

    @property
    def memory_size(self) -> bytes:
        return b'\x08' if self.size == '1K' else b'\x20'


def _encode_value(value: int, address: int) -> bytes:
    v = struct.pack('<i', value)
    inv = bytes(b ^ 0xFF for b in v)
    a = address & 0xFF
    return v + inv + v + bytes([a, a ^ 0xFF, a, a ^ 0xFF])


def _decode_value(data: bytes) -> Optional[int]:
    v, inv, v2 = data[0:4], data[4:8], data[8:12]
    if v != v2 or any((x ^ 0xFF) != y for x, y in zip(v, inv)):
        return None
    if data[12] != data[14] or data[13] != data[15] or data[12] ^ 0xFF != data[13]:
        return None
    return int(struct.unpack('<i', v)[0])


class _Nak(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


class SimulatedReader:
    """A serial-port stand-in that answers like a GNetPlus MIFARE reader.

    Pass it to `MifareReader.from_serial()`, or use `MifareReader.simulated()`
    which creates one for you. Thread-safe: you can `place_card()` from another
    thread while `wait_for_card()` is waiting.

    Args:
        card: Card to start with in the field, or None for an empty reader.
        version: Version string returned by GET_VERSION.

    Attributes:
        card: The card currently in the field (None if none).
        auto_mode: Whether the reader sends card-arrival events.
        queries: Every query frame received, as `QueryMessage` objects, for assertions.
    """

    def __init__(self, card: Optional[SimulatedCard] = None,
                 version: str = 'SIM0001 V1.0 (mifarepy simulator)') -> None:
        self.card = card
        self.version = version
        self.auto_mode = False
        self.rf_on = True
        self.queries: list[QueryMessage] = []
        self.timeout: Optional[float] = None
        self.is_open = True
        self.port = 'simulated'
        self._incoming = b''
        self._pending: list[bytes] = []   # responses not yet "arrived"
        self._buffer = b''                # responses available to read()
        self._cond = threading.Condition()
        self._keys: dict[tuple[int, int], bytes] = {}
        self._last_key: dict[int, bytes] = {}  # key type -> last key loaded
        self._auth: Optional[tuple[int, int]] = None   # (sector, key type)
        self._selected = False
        self._transfer_buffer: Optional[int] = None

    # -- test controls ----------------------------------------------------

    def place_card(self, card: SimulatedCard) -> None:
        """Put *card* in the field (replacing any other). Sends an event in auto mode."""
        with self._cond:
            self.card = card
            card.halted = False
            self._deselect()
            if self.auto_mode:
                self._pending.append(bytes(ResponseMessage(0, ResponseMessage.EVN, b'I')))
            self._cond.notify_all()

    def remove_card(self) -> None:
        """Take the card out of the field."""
        with self._cond:
            self.card = None
            self._deselect()

    # -- serial.Serial interface -----------------------------------------

    def write(self, data: bytes) -> int:
        with self._cond:
            self._incoming += bytes(data)
            while True:
                frame = self._take_frame()
                if frame is None:
                    break
                self._pending.extend(self._handle(frame))
            self._cond.notify_all()
        return len(data)

    def read(self, size: int = 1) -> bytes:
        with self._cond:
            if not self._buffer and not self._pending and self.timeout != 0:
                self._cond.wait(timeout=self.timeout if self.timeout is not None else 1.0)
            if not self._buffer and self._pending:
                self._buffer = b''.join(self._pending)
                self._pending.clear()
            chunk, self._buffer = self._buffer[:size], self._buffer[size:]
            return chunk

    def reset_input_buffer(self) -> None:
        with self._cond:
            self._buffer = b''

    def close(self) -> None:
        self.is_open = False

    @property
    def in_waiting(self) -> int:
        return len(self._buffer) + sum(len(p) for p in self._pending)

    # -- protocol ---------------------------------------------------------

    def _take_frame(self) -> Optional[QueryMessage]:
        buf = self._incoming
        start = buf.find(bytes([Message.SOH]))
        if start < 0:
            self._incoming = b''
            return None
        buf = buf[start:]
        if len(buf) < 4 or len(buf) < 4 + buf[3] + 2:
            self._incoming = buf
            return None
        size = 4 + buf[3] + 2
        frame, self._incoming = buf[:size], buf[size:]
        try:
            return QueryMessage.readfrom(BytesIO(frame))  # type: ignore[arg-type]
        except InvalidMessage:
            return None

    def _handle(self, query: QueryMessage) -> list[bytes]:
        self.queries.append(query)
        try:
            data, extra = self._dispatch(query.function, query.data)
            frames = [bytes(ResponseMessage(query.address, ResponseMessage.ACK, data))]
            return frames + extra
        except _Nak as nak:
            return [bytes(ResponseMessage(query.address, ResponseMessage.NAK, bytes([nak.code])))]

    def _card(self) -> SimulatedCard:
        if self.card is None or not self.rf_on:
            raise _Nak(NAK_NO_TAG)
        return self.card

    def _deselect(self) -> None:
        self._selected = False
        self._auth = None

    def _block(self, rel: int) -> int:
        if self._auth is None:
            raise _Nak(NAK_NOT_AUTH)
        sector = self._auth[0]
        if not 0 <= rel < layout.blocks_in_sector(sector):
            raise _Nak(NAK_PARAM)
        return layout.absolute_block(sector, rel)

    def _dispatch(self, f: int, d: bytes) -> tuple[bytes, list[bytes]]:
        Q = QueryMessage
        if f == Q.POLLING:
            return b'', []
        if f == Q.GET_VERSION:
            return self.version.encode('latin1') + b'\x00', []
        if f == Q.ECHO:
            return d, []
        if f in (Q.AUTO_MODE, Q.ENABLE_AUTO_MODE):
            self.auto_mode = bool(d[:1] == b'\x01')
            extra = []
            if self.auto_mode and self.card is not None and self.rf_on:
                extra.append(bytes(ResponseMessage(0, ResponseMessage.EVN, b'I')))
            return bytes([int(self.auto_mode)]), extra
        if f == Q.RF_POWER_ONOFF:
            self.rf_on = d[:1] == b'\x01'
            self._deselect()
            if self.card is not None:
                self.card.halted = False
            return b'', []
        if f == Q.SAVE_KEY:
            if len(d) != 8 or d[0] not in (KEY_A, KEY_B):
                raise _Nak(NAK_PARAM)
            self._keys[(d[0], d[1])] = d[2:8]
            self._last_key[d[0]] = d[2:8]
            return b'', []

        card = self._card()
        if f in (Q.REQUEST, Q.REQUEST_ALL):
            if card.halted and f == Q.REQUEST:
                raise _Nak(NAK_NO_TAG)
            card.halted = False
            self._deselect()
            return card.atqa, []
        if f == Q.ANTI_COLLISION:
            return card.uid, []
        if f == Q.SELECT_CARD:
            if d != card.uid:
                raise _Nak(NAK_NO_TAG)
            self._selected = True
            self._auth = None
            return card.memory_size, []
        if f == Q.HALT:
            card.halted = True
            self._deselect()
            return b'', []
        if f == Q.GET_SECOND_SN:
            raise _Nak(NAK_PARAM)  # Ultralight only
        if f in (Q.AUTHENTICATE, Q.AUTHENTICATE_KEY):
            return self._authenticate(card, f, d), []

        if f == Q.READ_BLOCK:
            blk = self._block(d[0])
            data = bytes(card.memory[blk])
            if layout.sector_of(blk)[1] == layout.trailer_block(layout.sector_of(blk)[0]):
                data = b'\x00' * 6 + data[6:]   # Key A is never readable
            return data, []
        if f == Q.WRITE_BLOCK:
            if len(d) != 17:
                raise _Nak(NAK_PARAM)
            blk = self._block(d[0])
            if blk == 0:
                raise _Nak(0x0F)  # manufacturer block is read-only
            card.memory[blk][:] = d[1:]
            return b'', []
        if f == Q.READ_VALUE:
            blk = self._block(d[0])
            value = _decode_value(bytes(card.memory[blk]))
            if value is None:
                raise _Nak(NAK_READ)
            return struct.pack('<i', value), []
        if f == Q.CREATE_VALUE_BLOCK:
            blk = self._block(d[0])
            value = struct.unpack('<i', d[1:5])[0] if len(d) >= 5 else 0
            card.memory[blk][:] = _encode_value(value, blk)
            return b'', []
        if f in (Q.SET_VALUE, Q.SET_VALUEEX):
            blk = self._block(d[0])
            current = _decode_value(bytes(card.memory[blk]))
            if current is None or len(d) != 6 or d[1] not in (0xC0, 0xC1):
                raise _Nak(NAK_TRANSFER)
            delta = struct.unpack('<i', d[2:6])[0]
            new = current + delta if d[1] == 0xC1 else current - delta
            if f == Q.SET_VALUE:
                card.memory[blk][:] = _encode_value(new, blk)
            else:
                self._transfer_buffer = new
            return b'', []
        if f == Q.RESTORE:
            blk = self._block(d[0])
            value = _decode_value(bytes(card.memory[blk]))
            if value is None:
                raise _Nak(NAK_TRANSFER)
            self._transfer_buffer = value
            return b'', []
        if f == Q.TRANSFER:
            blk = self._block(d[0])
            if self._transfer_buffer is None:
                raise _Nak(NAK_TRANSFER)
            card.memory[blk][:] = _encode_value(self._transfer_buffer, blk)
            return b'', []
        raise _Nak(NAK_UNKNOWN)

    def _authenticate(self, card: SimulatedCard, f: int, d: bytes) -> bytes:
        if len(d) < 2 or d[0] not in (KEY_A, KEY_B):
            raise _Nak(NAK_PARAM)
        key_type, sector = d[0], d[1]
        if sector >= card.sectors:
            raise _Nak(NAK_PARAM)
        if not self._selected:
            raise _Nak(NAK_AUTH)
        if f == QueryMessage.AUTHENTICATE_KEY:
            # With a key in the payload use it; otherwise re-use the last loaded key.
            key = d[2:8] if len(d) == 8 else self._last_key.get(key_type)
        else:
            key = self._keys.get((key_type, sector))
        key_a, key_b = card.keys(sector)
        expected = key_a if key_type == KEY_A else key_b
        if key is None or key != expected:
            self._deselect()   # a failed authentication drops the card to IDLE
            raise _Nak(NAK_AUTH)
        self._auth = (sector, key_type)
        return b''
