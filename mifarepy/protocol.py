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

import logging
import struct
from dataclasses import dataclass
from typing import Literal, Optional, Union

import serial

logger = logging.getLogger(__name__)


class InvalidMessage(Exception):
    """Raised when an invalid message is received from the RFID reader.

    Attributes:
        raw_bytes: The partial bytes that were read from the serial port before
                   the error occurred.  Useful for low-level debugging.
    """

    def __init__(self, message: str, raw_bytes: bytes = b'') -> None:
        super().__init__(message)
        self.raw_bytes = raw_bytes


# Mapping of NAK payload bytes to human-readable descriptions, following the
# error-code table in the GIGA-TMS MIFARE Application Programming Guide
# (TM970014, Annex B).  0x0X-0x3X are card/MIFARE errors; 0xE0-0xE6 are
# GNetPlus framing/protocol errors.
_NAK_CODES: dict[bytes, str] = {
    b'\x03': 'Empty',
    b'\x04': 'Authentication error',
    b'\x09': 'Key error',
    b'\x0A': 'Not authenticated',
    b'\x0E': 'Transfer error',
    b'\x0F': 'Write error',
    b'\x10': 'Increment error',
    b'\x11': 'Decrement error',
    b'\x12': 'Read error',
    b'\x1C': 'Access timeout',
    b'\x1F': 'No tag in field',
    b'\x27': 'Wrong parameter value',
    b'\x2D': 'Host authentication error',
    b'\x2F': 'Wrong DES key',
    b'\x33': 'DES key load error',
    b'\xE0': 'Command denied',
    b'\xE1': 'Illegal command',
    b'\xE2': 'Command overrun',
    b'\xE3': 'Packet CRC error',
    b'\xE4': 'Out of memory',
    b'\xE5': 'Out of frame',
    b'\xE6': 'Unknown command',
}


class GNetPlusError(Exception):
    """
    Exception thrown when receiving a NAK (negative acknowledge) response.

    Attributes:
        raw: Raw NAK payload bytes from the reader.
        code_description: Human-readable description of the NAK code if known.
    """

    def __init__(self, message: str, raw: bytes = b'') -> None:
        super().__init__(message)
        self.raw = raw
        self.code_description: str = _NAK_CODES.get(raw, 'Unknown error')
        #: Integer NAK code (``raw[0]``), or ``0`` when raw is not a single byte.
        self.nak_code: int = raw[0] if len(raw) == 1 else 0


@dataclass
class SectorAuth:
    """Per-sector authentication configuration for `read_blocks()`
    and `write_blocks()`.

    Pass a ``dict[sector, SectorAuth]`` to the ``auth`` keyword argument of
    those methods to supply per-sector keys in a discoverable, IDE-friendly
    way instead of the legacy ``keys=`` / ``key_types=`` dict juggling.

    Attributes:
        key:      6-byte MIFARE authentication key.
        key_type: ``'A'`` (default) or ``'B'``.
        timeout:  Per-sector auth timeout in seconds (default ``1.0``).
        flush:    Flush the serial input buffer before reading (default ``True``).

    Usage example:

    ```python
    from mifarepy import SectorAuth

    reader.read_blocks(
        {1: [0, 1], 2: [0]},
        auth={
            1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
            2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
        },
    )
    ```
    """

    key: bytes
    key_type: Literal['A', 'B'] = 'A'
    timeout: float = 1.0
    flush: bool = True

    def __post_init__(self) -> None:
        if self.key_type not in ('A', 'B'):
            raise ValueError("key_type must be 'A' or 'B'")
        if len(self.key) != 6:
            raise ValueError('key must be exactly 6 bytes')


@dataclass
class CardInfo:
    """Information about a card detected and selected in the RF field.

    Returned by `scan_tag()`.  Provides the UID
    in multiple representations so callers can use whatever is most convenient
    without extra conversion.

    Attributes:
        uid:       UID formatted as ``'0xAABBCCDD'`` (always uppercase, zero-padded).
        uid_int:   Unsigned 32-bit integer.
        uid_bytes: Raw 4-byte response from ANTI_COLLISION (little-endian byte order).

    Usage example:

    ```python
    card = reader.scan_tag()
    print(card)                  # '0xEDCEF8C3'
    print(card.uid_int)          # 3989956803
    print(card.uid_bytes.hex())  # 'c3f8ceed'
    ```
    """

    uid: str
    uid_int: int
    uid_bytes: bytes

    def __str__(self) -> str:
        return self.uid

    def __repr__(self) -> str:
        return f'CardInfo(uid={self.uid!r})'


def gencrc(msg_bytes: bytes) -> int:
    """
    Generate a 16-bit CRC checksum.

    Args:
        msg_bytes: bytes containing message for checksum

    Returns:
        16-bit integer containing CRC checksum
    """
    crc = 0xFFFF

    for byte in msg_bytes:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1

    return crc


class Message:
    """
    Base class representing a message for the RFID reader.
    """

    SOH = 0x01  # Start of Header

    def __init__(self, address: int, function: int, data: Union[bytes, str]):
        """
        Initialize a message.

        Args:
            address: 8-bit device address (use 0 unless specified).
            function: 8-bit function code representing the message type.
            data: Message payload (bytes or string).
        """
        self.address = address
        self.function = function
        self.data = data.encode('latin1') if isinstance(data, str) else data

    def __bytes__(self) -> bytes:
        """
        Converts Message to raw binary form suitable for transmission.

        Returns:
            Bytes representation of the message.
        """
        msg_bytes = struct.pack('BBB', self.address, self.function, len(self.data)) + self.data
        crc = gencrc(msg_bytes)

        return bytes([self.SOH]) + msg_bytes + struct.pack('>H', crc)

    def __str__(self) -> str:
        """
        Returns hex representation of the message.

        Returns:
            Hexadecimal string representation.
        """
        return self.__bytes__().hex()

    def __repr__(self) -> str:
        return f'Message(address={hex(self.address)}, function={hex(self.function)}, data={self.data!r})'

    def sendto(self, serial_port):
        """
        Sends this message to the provided serial port.

        Args:
            serial_port: Serial port to send the message.
        """
        serial_port.write(bytes(self))

    @classmethod
    def readfrom(cls, serial_port: serial.Serial):
        """
        Reads a message from the serial port and constructs a Message instance.

        Args:
            serial_port: Serial interface to read from.

        Returns:
            Constructed Message instance.

        Raises:
            InvalidMessage: If message is incomplete or invalid.
        """
        header = serial_port.read(4)

        if len(header) < 4:
            raise InvalidMessage('Incomplete header', raw_bytes=header)

        soh, address, function, length = struct.unpack('BBBB', header)

        if soh != cls.SOH:
            raise InvalidMessage('SOH does not match', raw_bytes=header)

        data = serial_port.read(length)
        crc = serial_port.read(2)
        if len(data) < length or len(crc) < 2:
            raise InvalidMessage('Incomplete data or CRC', raw_bytes=header + data + crc)

        msg = cls(address=address, function=function, data=data)
        if bytes(msg)[-2:] != crc:
            raise InvalidMessage('CRC does not match', raw_bytes=header + data + crc)

        return msg


class QueryMessage(Message):
    """
    A query message sent from the host to the reader.

    Function codes follow the GNetPlus common command table (0x00-0x1F) and the
    MIFARE application command table (0x20-0x3F).
    """
    POLLING = 0x00
    GET_VERSION = 0x01
    SET_SLAVE_ADDR = 0x02
    LOGON = 0x03
    LOGOFF = 0x04
    SET_PASSWORD = 0x05
    CLASSNAME = 0x06
    SET_DATETIME = 0x07
    GET_DATETIME = 0x08
    GET_REGISTER = 0x09
    SET_REGISTER = 0x0A
    RECORD_COUNT = 0x0B
    GET_FIRST_RECORD = 0x0C
    GET_NEXT_RECORD = 0x0D
    ERASE_ALL_RECORDS = 0x0E
    ADD_RECORD = 0x0F
    RECOVER_ALL_RECORDS = 0x10
    DO = 0x11
    DI = 0x12
    ANALOG_INPUT = 0x13
    THERMOMETER = 0x14
    GET_NODE = 0x15
    GET_SN = 0x16
    SILENT_MODE = 0x17
    RESERVE = 0x18
    ENABLE_AUTO_MODE = 0x19
    GET_TIME_ADJUST = 0x1A
    ECHO = 0x1B  # 0x18 was wrong (collision with RESERVE); correct value per GNetPlus spec
    SET_TIME_ADJUST = 0x1C
    DEBUG = 0x1D
    RESET = 0x1E
    GO_TO_ISP = 0x1F
    REQUEST = 0x20
    ANTI_COLLISION = 0x21
    SELECT_CARD = 0x22
    AUTHENTICATE = 0x23
    READ_BLOCK = 0x24
    WRITE_BLOCK = 0x25
    SET_VALUE = 0x26
    READ_VALUE = 0x27
    CREATE_VALUE_BLOCK = 0x28
    ACCESS_CONDITION = 0x29
    HALT = 0x2A
    SAVE_KEY = 0x2B
    GET_SECOND_SN = 0x2C
    GET_ACCESS_CONDITION = 0x2D
    AUTHENTICATE_KEY = 0x2E
    REQUEST_ALL = 0x2F
    SET_VALUEEX = 0x32
    TRANSFER = 0x33
    RESTORE = 0x34
    GET_SECTOR = 0x3D
    RF_POWER_ONOFF = 0x3E
    AUTO_MODE = 0x3F


class ResponseMessage(Message):
    """
    Message received from the RFID reader.
    """
    ACK = 0x06  # Acknowledge
    NAK = 0x15  # Negative Acknowledge
    EVN = 0x12  # Event Notification

    # Known EVN payload byte for card insertion event.
    EVN_CARD_IN: bytes = b'I'

    def to_error(self) -> Optional[GNetPlusError]:
        """
        Convert a NAK response into a GNetPlusError with code description.

        Returns:
            GNetPlusError if this is a NAK response, else None.
        """
        if self.function == self.NAK:
            desc = _NAK_CODES.get(self.data, 'Unknown error')
            return GNetPlusError(
                f'NAK received — {desc} (raw={self.data!r})',
                raw=self.data,
            )
        return None
