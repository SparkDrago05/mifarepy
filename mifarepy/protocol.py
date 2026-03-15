import logging
import serial
import struct
from dataclasses import dataclass
from typing import Literal, Optional, Union

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


# Mapping of known NAK payload bytes to human-readable descriptions.
# Based on GNetPlus® protocol documentation.
_NAK_CODES: dict[bytes, str] = {
    b'\x01': 'Invalid command',
    b'\x02': 'Invalid length',
    b'\x03': 'CRC error',
    b'\x04': 'Invalid address',
    b'\x05': 'Authentication failed',
    b'\x06': 'Card not present',
    b'\x07': 'Read error',
    b'\x08': 'Write error',
    b'\x09': 'Invalid block',
    b'\x0A': 'Invalid sector',
    b'\x0B': 'Invalid key',
    b'\x0C': 'Timeout',
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
    """Per-sector authentication configuration for :meth:`~mifarepy.MifareReader.read_blocks`
    and :meth:`~mifarepy.MifareReader.write_blocks`.

    Pass a ``dict[sector, SectorAuth]`` to the ``auth`` keyword argument of
    those methods to supply per-sector keys in a discoverable, IDE-friendly
    way instead of the legacy ``keys=`` / ``key_types=`` dict juggling.

    Fields:
        key:      6-byte MIFARE authentication key.
        key_type: ``'A'`` (default) or ``'B'``.
        timeout:  Per-sector auth timeout in seconds (default ``1.0``).
        flush:    Flush the serial input buffer before reading (default ``True``).

    Example::

        from mifarepy import SectorAuth

        reader.read_blocks(
            {1: [0, 1], 2: [0]},
            auth={
                1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
                2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
            },
        )
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

    Returned by :meth:`~mifarepy.MifareReader.scan_tag`.  Provides the UID
    in multiple representations so callers can use whatever is most convenient
    without extra conversion.

    Fields:
        uid:       UID formatted as ``'0xAABBCCDD'`` (always uppercase, zero-padded).
        uid_int:   Unsigned 32-bit integer.
        uid_bytes: Raw 4-byte response from ANTI_COLLISION (little-endian byte order).

    Example::

        card = reader.scan_tag()
        print(card)                  # '0xEDCEF8C3'
        print(card.uid_int)          # 3989956803
        print(card.uid_bytes.hex())  # 'c3f8ceed'
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

    @param msg_bytes: bytes containing message for checksum
    @returns 16-bit integer containing CRC checksum
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

        @param address: 8-bit device address (use 0 unless specified).
        @param function: 8-bit function code representing the message type.
        @param data: Message payload (bytes or string).
        """
        self.address = address
        self.function = function
        self.data = data.encode('latin1') if isinstance(data, str) else data

    def __bytes__(self) -> bytes:
        """
        Converts Message to raw binary form suitable for transmission.

        @return: Bytes representation of the message.
        """
        msg_bytes = struct.pack('BBB', self.address, self.function, len(self.data)) + self.data
        crc = gencrc(msg_bytes)

        return bytes([self.SOH]) + msg_bytes + struct.pack('>H', crc)

    def __str__(self) -> str:
        """
        Returns hex representation of the message.

        @return: Hexadecimal string representation.
        """
        return self.__bytes__().hex()

    def __repr__(self) -> str:
        return f'Message(address={hex(self.address)}, function={hex(self.function)}, data={self.data!r})'

    def sendto(self, serial_port):
        """
        Sends this message to the provided serial port.

        @param serial_port: Serial port to send the message.
        """
        serial_port.write(bytes(self))

    @classmethod
    def readfrom(cls, serial_port: serial.Serial):
        """
        Reads a message from the serial port and constructs a Message instance.

        @param serial_port: Serial interface to read from.
        @return: Constructed Message instance.
        @raises InvalidMessage: If message is incomplete or invalid.
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
    A query message to be sent from host machine to card reader device. Magical constants taken from protocol documentation.
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

        @returns GNetPlusError if this is a NAK response, else None.
        """
        if self.function == self.NAK:
            desc = _NAK_CODES.get(self.data, 'Unknown error')
            return GNetPlusError(
                f'NAK received — {desc} (raw={self.data!r})',
                raw=self.data,
            )
        return None
