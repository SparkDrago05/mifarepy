# mifarepy -- Python library for interfacing with PROMAG RFID card reader
# Adapted from https://github.com/harishpillay/gnetplus (initially in Python 2)
#
# Authors:
#     Original: Chow Loong Jin <lchow@redhat.com>
#     Original: Harish Pillay <hpillay@redhat.com>
#     Adapted by: Spark Drago <https://github.com/SparkDrago05>
#
# This library is released under the GNU Lesser General Public License v3.0 or later.
# See the LICENCE file for more details.


"""
mifarepy: A Python library for interfacing with the PROMAG RFID card reader
using the GNetPlus® protocol.

Features:
- Communicates via serial interface (`pyserial`).
- Supports various RFID commands (get serial number, read/write blocks, etc.).
- Includes error handling for invalid messages and device errors.

Example:
    from mifarepy import MifareReader

    with MifareReader('/dev/ttyUSB0') as reader:
        print('S/N:', reader.get_sn(endian='little', as_string=True))

License:
    GNU Lesser General Public Licence v3.0 or later
"""

import asyncio
import logging
import serial
import struct
import time
import warnings
from typing import Literal, Optional, Union, overload
from .protocol import CardInfo, GNetPlusError, QueryMessage, ResponseMessage, SectorAuth

logger = logging.getLogger(__name__)


class MifareReader:
    """
    Class for interfacing with the RFID card reader.

    Can be used as a context manager to ensure the serial port is closed::

        with MifareReader('/dev/ttyUSB0') as reader:
            uid = reader.get_sn()
    """

    def __init__(self, port: str = '/dev/ttyUSB0', baudrate: int = 19200, deviceaddr: int = 0, **kwargs):
        """
        Initialize the RFID reader connection.

        @param port: Serial port name (e.g., '/dev/ttyUSB0').
        @param baudrate: Baudrate for interfacing with the device. Don't change this unless you know what you're doing.
        @param deviceaddr: Device address (default: 0).
        @raises RuntimeError: If the serial port cannot be opened.
        """
        self.port = port
        self.baudrate = baudrate
        self.deviceaddr = deviceaddr

        try:
            self.serial = serial.Serial(port, baudrate=baudrate, **kwargs)
        except serial.SerialException as pe:
            raise RuntimeError(f'Unable to open port {port}: {pe}')

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Reset auto mode then close the underlying serial port.

        Disabling auto mode before closing ensures the reader is left in a
        clean, command-driven state so the next session does not receive
        spurious EVN events or NAK responses from a lingering event mode.
        """
        if hasattr(self, 'serial') and self.serial.isOpen():
            try:
                self.set_auto_mode(False)
            except Exception:
                pass  # best-effort; don't mask the real reason for close
            self.serial.close()

    def __enter__(self) -> 'MifareReader':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        state = 'open' if (hasattr(self, 'serial') and self.serial.isOpen()) else 'closed'
        return f'MifareReader(port={self.port!r}, baudrate={self.baudrate}, addr={self.deviceaddr}, {state})'

    # ------------------------------------------------------------------
    # Low-level send / receive
    # ------------------------------------------------------------------

    def sendmsg(self, function: int, data: bytes = b'') -> None:
        """
        Construct and send a QueryMessage to the RFID reader.

        @param function: @see Message.function
        @param data: @see Message.data
        """
        QueryMessage(self.deviceaddr, function, data).sendto(self.serial)

    def readmsg(self, sink_events: bool = False) -> ResponseMessage:
        """
        Read a message, optionally ignoring EVN (event) messages which are
        device-driven.

        @param sink_events: If True, silently discard EVN messages.
        @return: Constructed ResponseMessage instance.
        @raises GNetPlusError: If a NAK response is received.
        """
        while True:
            response = ResponseMessage.readfrom(self.serial)

            if sink_events and response.function == ResponseMessage.EVN:
                continue

            break

        if response.function == ResponseMessage.NAK:
            raise response.to_error()

        return response

    def _resolve_per_sector_param(self, param, sector, default):
        """
        Resolve a parameter that can be either a scalar (applied to all sectors)
        or a dict mapping sector number to a per-sector value.

        @param param: Scalar value or dict[sector -> value].
        @param sector: Current sector number being processed.
        @param default: Fallback if param is None or sector not in dict.
        @return: Resolved value for this sector.
        """
        if isinstance(param, dict):
            return param.get(sector, default)
        return param if param is not None else default

    # ------------------------------------------------------------------
    # Card discovery — private helpers
    # ------------------------------------------------------------------

    def _detect_card_uid(self) -> bytes:
        """Send REQUEST + ANTI_COLLISION; return the raw 4-byte UID bytes."""
        self.sendmsg(QueryMessage.REQUEST)
        self.readmsg(sink_events=True)
        self.sendmsg(QueryMessage.ANTI_COLLISION)
        return self.readmsg(sink_events=True).data

    def _detect_card_uid_all(self) -> bytes:
        """Send REQUEST_ALL + ANTI_COLLISION; return the raw 4-byte UID bytes.

        Unlike :meth:`_detect_card_uid`, this wakes HALT-state cards too.
        """
        self.sendmsg(QueryMessage.REQUEST_ALL)
        self.readmsg(sink_events=True)
        self.sendmsg(QueryMessage.ANTI_COLLISION)
        return self.readmsg(sink_events=True).data

    # ------------------------------------------------------------------
    # Card discovery — public API
    # ------------------------------------------------------------------

    def get_sn(self, endian: str = 'little', as_string: bool = True) -> Union[str, int]:
        """
        .. deprecated::
            Use :meth:`get_uid` (returns ``'0xAABBCCDD'`` string) or
            :meth:`get_uid_int` (returns unsigned integer) instead.

        Get the serial number of the card currently in the RF field.

        @param endian: ``'big'`` or ``'little'``.  Selects byte order for the
                       4-byte UID from the ANTI_COLLISION response.
        @param as_string: If ``True`` returns ``'0xAABBCCDD'`` hex string;
                          otherwise an unsigned integer.
        @return: Card UID as hex string or integer.
        """
        warnings.warn(
            'get_sn() is deprecated and will be removed in a future version. '
            'Use get_uid() or get_uid_int() instead.',
            DeprecationWarning,
            stacklevel=2,
        )
        uid_bytes = self._detect_card_uid()
        uid = struct.unpack('>L' if endian == 'big' else '<L', uid_bytes)[0]
        return f'0x{uid:08X}' if as_string else uid

    def get_uid(self) -> str:
        """
        Return the 4-byte UID of the card currently in the RF field as a
        zero-padded upper-case hex string (e.g. ``'0xEDCEF8C3'``).

        Internally runs REQUEST → ANTI_COLLISION.  Does *not* call SELECT;
        use :meth:`scan_tag` or :meth:`select_card` when you need the card
        to be in an active/authenticated state.

        @return: UID string like ``'0xAABBCCDD'``.
        @raises GNetPlusError: If no card is present or the reader returns NAK.
        """
        uid_bytes = self._detect_card_uid()
        uid = struct.unpack('<L', uid_bytes)[0]
        return f'0x{uid:08X}'

    def get_uid_int(self) -> int:
        """
        Return the 4-byte UID of the card currently in the RF field as an
        unsigned 32-bit integer (little-endian byte order).

        @return: Unsigned 32-bit UID integer.
        @raises GNetPlusError: If no card is present or the reader returns NAK.
        """
        uid_bytes = self._detect_card_uid()
        return struct.unpack('<L', uid_bytes)[0]

    def request_all(self, endian: str = 'little', as_string: bool = True) -> Union[str, int]:
        """
        Enumerate *all* cards in field (REQUEST_ALL + ANTI_COLLISION), including
        cards in HALT state.  Useful for multi-card scanning.

        @param endian: ``'big'`` or ``'little'`` byte order for the 4-byte UID.
        @param as_string: If ``True`` returns hex string; otherwise integer.
        @return: Card UID as hex string or integer.
        """
        uid_bytes = self._detect_card_uid_all()
        uid = struct.unpack('>L' if endian == 'big' else '<L', uid_bytes)[0]
        return f'0x{uid:08X}' if as_string else uid

    @overload
    def get_second_sn(self, as_string: Literal[True]) -> str: ...
    @overload
    def get_second_sn(self, as_string: Literal[False]) -> bytes: ...
    @overload
    def get_second_sn(self, as_string: bool = ...) -> Union[str, bytes]: ...
    def get_second_sn(self, as_string: bool = True) -> Union[str, bytes]:
        """
        Retrieve the secondary serial number (7-byte UID for MIFARE UltraLight /
        DESFire and other ISO 14443-3 compliant cards).

        @param as_string: If ``True`` returns hex string; otherwise raw bytes.
        @return: Secondary serial number as hex string or bytes.
        """
        self.sendmsg(QueryMessage.GET_SECOND_SN)
        response = self.readmsg()
        return response.data.hex() if as_string else response.data

    def select_card(self) -> bytes:
        """
        Run REQUEST → ANTI_COLLISION → SELECT_CARD to bring a card into
        the active state ready for authentication and block operations.

        Called automatically by :meth:`authenticate_sector` before every
        key-load / authenticate sequence, so you normally do not need to
        call this directly.  It is still public for advanced multi-card
        workflows (see example 08).

        @return: ACK payload bytes from the SELECT_CARD response.
        @raises GNetPlusError: If any step returns a NAK.
        """
        uid_bytes = self._detect_card_uid()
        self.sendmsg(QueryMessage.SELECT_CARD, uid_bytes)
        return self.readmsg().data

    def ping(self) -> bool:
        """
        Send a POLLING heartbeat to the reader and return ``True`` if it
        responds with ACK.

        Use this to verify the serial connection is alive without interacting
        with any card.  The reader responds even when no card is present.

        @return: ``True`` if the reader acknowledged the POLLING command.
        @raises GNetPlusError: If the reader explicitly NAKs (unusual).
        """
        try:
            self.sendmsg(QueryMessage.POLLING)
            self.readmsg(sink_events=True)
            return True
        except GNetPlusError:
            return False

    def is_card_present(self) -> bool:
        """
        Non-blocking check: send a single REQUEST and return whether any
        card responded.

        Does **not** select or authenticate the card — use :meth:`scan_tag`
        or :meth:`select_card` for that.

        @return: ``True`` if a card is in the RF field, ``False`` otherwise.
        """
        try:
            self.sendmsg(QueryMessage.REQUEST)
            self.readmsg(sink_events=True)
            return True
        except GNetPlusError:
            return False

    def scan_tag(self) -> CardInfo:
        """
        One-shot card detection: REQUEST → ANTI_COLLISION → SELECT_CARD.

        Returns a :class:`~mifarepy.protocol.CardInfo` dataclass with the
        UID available in multiple representations.  The card is left in
        the *active* state so you can immediately call
        :meth:`authenticate_sector` / :meth:`read_block` etc.

        Example::

            card = reader.scan_tag()
            print(card)            # '0xEDCEF8C3'
            print(card.uid_int)    # 3989956803

        @return: :class:`CardInfo` with ``uid``, ``uid_int``, and ``uid_bytes``.
        @raises GNetPlusError: If no card is present or any step fails.
        """
        uid_bytes = self._detect_card_uid()
        self.sendmsg(QueryMessage.SELECT_CARD, uid_bytes)
        self.readmsg()
        uid_int = struct.unpack('<L', uid_bytes)[0]
        return CardInfo(
            uid=f'0x{uid_int:08X}',
            uid_int=uid_int,
            uid_bytes=uid_bytes,
        )

    def wait_for_card(self, timeout: int = 10) -> Optional[str]:
        """
        Check if a card is already present; if not, wait for a card-insert event.

        @param timeout: Maximum time to wait in seconds (default: 10).
        @return: Card serial number string.
        @raises TimeoutError: If no card is detected within the timeout.
        """
        self.set_auto_mode()

        try:
            card_sn = self.get_uid()
            if card_sn:
                logger.info('Card already present: %s', card_sn)
                return card_sn
        except GNetPlusError:
            pass  # No card yet; wait for EVN

        start_time = time.time()
        while time.time() - start_time < timeout:
            response = self.readmsg()
            if (response.function == ResponseMessage.EVN
                    and ResponseMessage.EVN_CARD_IN in response.data):
                logger.info('Card insertion event received')
                return self.get_uid()
            time.sleep(0.1)

        raise TimeoutError('No card detected within the time limit')

    async def wait_for_card_async(self, timeout: float = 10.0) -> str:
        """
        Async variant of ``wait_for_card``. Does not block the event loop —
        serial I/O runs in a thread-pool executor.

        Suitable for use inside ``asyncio``-based applications (FastAPI,
        Django async views, automation scripts using ``asyncio.run``).

        Example::

            import asyncio
            from mifarepy import MifareReader

            async def main():
                with MifareReader('/dev/ttyUSB0') as reader:
                    uid = await reader.wait_for_card_async(timeout=15)
                    print('Card:', uid)

            asyncio.run(main())

        @param timeout: Maximum seconds to wait (default: 10).
        @return: Card UID as hex string.
        @raises TimeoutError: If no card is detected within the timeout.
        """
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: self.wait_for_card(int(timeout))),
            timeout=timeout + 1,  # give the inner timeout a chance to fire first
        )

    # ------------------------------------------------------------------
    # Reader control
    # ------------------------------------------------------------------

    def get_version(self) -> str:
        """
        Get product version string.

        @return: Firmware/hardware version string from the connected reader.
        """
        self.sendmsg(QueryMessage.GET_VERSION)
        response = self.readmsg().data
        return response.decode('latin1', errors='ignore').strip()

    def set_auto_mode(self, enabled: bool = True) -> bytes:
        """
        Toggle auto mode — whether the device emits EVN events when a card enters field.

        @param enabled: True to enable, False to disable.
        @return: Confirmed mode byte from the device.
        @raises GNetPlusError: If the device reports failure to set the mode.
        """
        mode = b'\x01' if enabled else b'\x00'
        self.sendmsg(QueryMessage.AUTO_MODE, mode)
        response = self.readmsg(sink_events=True)

        if response.data != mode:
            raise GNetPlusError('Failed to set auto mode')
        return response.data

    def halt(self) -> None:
        """
        Send HALT to deselect the current card and put it into HALT state.

        The card will not respond to subsequent REQUEST commands (only REQUEST_ALL).
        Call this after finishing operations on a card in multi-card scenarios.

        @raises GNetPlusError: If the reader returns a NAK.
        """
        self.sendmsg(QueryMessage.HALT)
        self.readmsg()

    def rf_power(self, on: bool) -> None:
        """
        Switch the RF field power on or off.

        Turning the RF field off and back on can reset cards that are in an
        inconsistent state without physically removing them.

        @param on: True to power on the RF field, False to power it off.
        @raises GNetPlusError: If the reader returns a NAK.
        """
        self.sendmsg(QueryMessage.RF_POWER_ONOFF, b'\x01' if on else b'\x00')
        self.readmsg()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate_sector(self, sector: int, key: bytes, key_type: str = 'A', timeout: float = 1.0, flush: bool = True) -> None:
        """
        Load a key into the reader and authenticate the specified MIFARE Classic sector.

        @param sector: Sector number to authenticate (0-15 for 1K; 0-39 for 4K).
        @param key: 6-byte authentication key.
        @param key_type: 'A' for Key A (0x60) or 'B' for Key B (0x61).
        @param timeout: Timeout in seconds for reader responses.
        @param flush: Whether to flush the input buffer before reading responses.
        @raises ValueError: If key_type is invalid or key length is not 6 bytes.
        @raises GNetPlusError: If the reader returns NAK during key load or authentication.
        """
        if key_type not in ('A', 'B'):
            raise ValueError("key_type must be 'A' or 'B'")
        if len(key) != 6:
            raise ValueError('key must be exactly 6 bytes long')

        # Re-select the card so this call is safe after any write operation.
        # MIFARE cards fall back to IDLE after writes; without SELECT they will
        # refuse the subsequent AUTHENTICATE with "Invalid address" / "Card not present".
        self.select_card()

        auth_code = 0x60 if key_type == 'A' else 0x61

        # --- SAVE_KEY: load the key into the reader ---
        # Data format: [KeyTypeCode, SectorNumber] + KeyBytes
        payload = bytes([auth_code, sector]) + key
        self.sendmsg(QueryMessage.SAVE_KEY, payload)
        if flush:
            try:
                self.serial.reset_input_buffer()
            except AttributeError:
                pass
        # Brief pause to allow reader to complete internal key load
        time.sleep(0.05)

        orig_timeout = getattr(self.serial, 'timeout', None)
        self.serial.timeout = timeout
        try:
            self.readmsg()
        finally:
            self.serial.timeout = orig_timeout

        # --- AUTHENTICATE: authenticate the sector ---
        # Data format: [KeyTypeCode, SectorNumber]
        payload = bytes([auth_code, sector])
        self.sendmsg(QueryMessage.AUTHENTICATE, payload)
        orig_timeout = getattr(self.serial, 'timeout', None)
        self.serial.timeout = timeout
        try:
            self.readmsg()
        finally:
            self.serial.timeout = orig_timeout

    def authenticate_sector_cached(
        self,
        sector: int,
        key_type: Literal['A', 'B'] = 'A',
        timeout: float = 1.0,
    ) -> None:
        """Authenticate a sector using a key that is **already loaded** in the reader.

        Skips the SAVE_KEY step (opcode 0x2C) and jumps straight to
        AUTHENTICATE_KEY (opcode 0x2E).  This is faster when the same key
        has already been loaded by a previous :meth:`authenticate_sector` call
        in the same session.

        .. warning::
            The reader only stores **one** key internally.  If any other sector
            was authenticated (or the reader was reset) since the last
            SAVE_KEY, call :meth:`authenticate_sector` instead.

        @param sector:   Sector to authenticate (0-15 for 1K; 0-39 for 4K).
        @param key_type: ``'A'`` for Key A (0x60) or ``'B'`` for Key B (0x61).
        @param timeout:  Timeout in seconds for the reader response.
        @raises ValueError:      If ``key_type`` is invalid.
        @raises GNetPlusError:   If the reader returns NAK.
        """
        if key_type not in ('A', 'B'):
            raise ValueError("key_type must be 'A' or 'B'")

        self.select_card()

        auth_code = 0x60 if key_type == 'A' else 0x61
        payload = bytes([auth_code, sector])
        self.sendmsg(QueryMessage.AUTHENTICATE_KEY, payload)

        orig_timeout = getattr(self.serial, 'timeout', None)
        self.serial.timeout = timeout
        try:
            self.readmsg()
        finally:
            self.serial.timeout = orig_timeout

    @overload
    def read_block(self, block: int, raw: Literal[True]) -> bytes: ...
    @overload
    def read_block(self, block: int, raw: Literal[False] = ...) -> str: ...
    @overload
    def read_block(self, block: int, raw: bool = ...) -> Union[bytes, str]: ...
    def read_block(self, block: int, raw: bool = False) -> Union[bytes, str]:
        """
        Read a single 16-byte block from the currently authenticated sector.

        @param block: Block index relative to the authenticated sector (0-3).
        @param raw: If True returns bytes; if False returns hex string.
        @return: Block data as bytes (raw=True) or hex string (raw=False).
        @raises GNetPlusError: If the read fails.
        """
        self.sendmsg(QueryMessage.READ_BLOCK, bytes([block]))
        response = self.readmsg()
        return response.data if raw else response.data.hex()

    def write_block(self, block: int, data: "Union[str, bytes]") -> str:
        """
        Write a 16-byte block to the currently authenticated sector.

        @param block: Block index relative to the authenticated sector (0-3).
        @param data: Data to write -- exactly 16 bytes or a 32-character hex string.
        @return: Reader's echoed data in hex format.
        @raises ValueError: If data is not exactly 16 bytes.
        @raises GNetPlusError: If the write fails.
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)
        if len(data) != 16:
            raise ValueError('Data must be exactly 16 bytes long')
        self.sendmsg(QueryMessage.WRITE_BLOCK, bytes([block]) + data)
        return self.readmsg().data.hex()

    # ------------------------------------------------------------------
    # Value block operations
    # ------------------------------------------------------------------

    def read_value(self, block: int) -> int:
        """
        Read a signed 32-bit value from a MIFARE value block.

        @param block: Block index relative to the authenticated sector (0-2).
        @return: Signed 32-bit integer stored in the value block.
        @raises GNetPlusError: If the read fails.
        """
        self.sendmsg(QueryMessage.READ_VALUE, bytes([block]))
        response = self.readmsg()
        return struct.unpack('<i', response.data[:4])[0]

    def write_value(self, block: int, value: int) -> None:
        """
        Write a signed 32-bit value to a MIFARE value block.

        Delegates to CREATE_VALUE_BLOCK (0x28) which both creates and
        updates value blocks and is universally supported across all
        GNetPlus firmware versions.

        @param block: Block index relative to the authenticated sector (0-2).
        @param value: Signed 32-bit integer to store.
        @raises ValueError: If value is outside signed 32-bit range.
        @raises GNetPlusError: If the write fails.
        """
        if not (-2**31 <= value <= 2**31 - 1):
            raise ValueError('value must be a signed 32-bit integer')
        self.create_value_block(block, value)

    def create_value_block(self, block: int, initial_value: int = 0) -> None:
        """
        Initialize a block as a MIFARE value block with the GNetPlus redundant
        format (value stored three times: twice normal, once inverted).

        Must authenticate the sector before calling.

        @param block: Block index relative to the authenticated sector (0-2).
        @param initial_value: Signed 32-bit starting value (default: 0).
        @raises ValueError: If initial_value is outside signed 32-bit range.
        @raises GNetPlusError: If the operation fails.
        """
        if not (-2**31 <= initial_value <= 2**31 - 1):
            raise ValueError('initial_value must be a signed 32-bit integer')
        payload = bytes([block]) + struct.pack('<i', initial_value)
        self.sendmsg(QueryMessage.CREATE_VALUE_BLOCK, payload)
        self.readmsg()

    def increment_value(self, block: int, delta: int) -> None:
        """
        Add *delta* to a MIFARE value block.

        Implemented as read → add → write using READ_VALUE / SET_VALUE because
        those are universally supported across all GNetPlus firmware versions.

        @param block: Block index relative to the authenticated sector (0-2).
        @param delta: Positive integer amount to add.
        @raises ValueError: If delta ≤ 0 or if the result overflows int32.
        @raises GNetPlusError: If the reader returns a NAK.
        """
        if delta <= 0 or delta > 2**31 - 1:
            raise ValueError('delta must be a positive 32-bit integer')
        current = self.read_value(block)
        new_val = current + delta
        if not (-2**31 <= new_val <= 2**31 - 1):
            raise ValueError(
                f'Increment overflows signed 32-bit range: {current} + {delta} = {new_val}'
            )
        self.write_value(block, new_val)

    def decrement_value(self, block: int, delta: int) -> None:
        """
        Subtract *delta* from a MIFARE value block.

        Implemented as read → subtract → write using READ_VALUE / SET_VALUE.

        @param block: Block index relative to the authenticated sector (0-2).
        @param delta: Positive integer amount to subtract.
        @raises ValueError: If delta ≤ 0 or if the result underflows int32.
        @raises GNetPlusError: If the reader returns a NAK.
        """
        if delta <= 0 or delta > 2**31 - 1:
            raise ValueError('delta must be a positive 32-bit integer')
        current = self.read_value(block)
        new_val = current - delta
        if not (-2**31 <= new_val <= 2**31 - 1):
            raise ValueError(
                f'Decrement underflows signed 32-bit range: {current} - {delta} = {new_val}'
            )
        self.write_value(block, new_val)

    def transfer(self, source_block: int, dest_block: int) -> None:
        """
        Copy the current value from *source_block* to *dest_block*.

        Both blocks must reside in the currently authenticated sector and must
        already be formatted as value blocks.

        @param source_block: Block to read the value from (0-2).
        @param dest_block: Block to write the value to (0-2).
        @raises GNetPlusError: If either the read or write fails.
        """
        value = self.read_value(source_block)
        self.write_value(dest_block, value)

    def restore(self, block: int) -> None:
        """
        Re-commit the current on-card value back to the block.

        With the read-modify-write implementation used here every write is
        immediately committed, so there is no in-flight state to undo.
        This method reads the block and writes it back to guarantee the value
        block format remains intact after any partial low-level failure.

        @param block: Block index relative to the authenticated sector (0-2).
        @raises GNetPlusError: If the reader returns a NAK.
        """
        value = self.read_value(block)
        self.write_value(block, value)

    # ------------------------------------------------------------------
    # Sector-level read / write
    # ------------------------------------------------------------------

    def read_sector(
        self,
        sector: "Optional[int]" = None,
        raw: bool = False,
        combine: bool = False,
    ) -> "Union[dict[int, Union[str, bytes]], Union[str, bytes]]":
        """
        Read data blocks 0, 1, and 2 of the currently authenticated sector
        (block 3 is the sector trailer and is intentionally skipped).

        Authenticate the sector with ``authenticate_sector`` before calling this.

        @param sector: Sector number -- used for logging only; does not affect
                       which blocks are read (authenticate separately).
        @param raw: If True returns bytes; otherwise hex strings.
        @param combine: If True concatenates all three blocks into a single value.
        @return: Dict mapping relative block index (0-2) to data, or combined value.
        @raises GNetPlusError: If any block read fails.
        """
        results: dict[int, Union[str, bytes]] = {}

        for block in range(3):
            results[block] = self.read_block(block, raw=raw)

        if combine:
            return b''.join(results.values()) if raw else ''.join(results.values())  # type: ignore[arg-type]

        return results

    def write_sector(self, data: "Union[str, bytes, dict[int, Union[str, bytes]]]") -> None:
        """
        Write data to blocks 0, 1, and/or 2 of the currently authenticated sector.

        Supported data shapes:
          - **16 bytes** / **32-char hex** -- same blob written to blocks 0, 1, and 2.
          - **48 bytes** / **96-char hex** -- split into three 16-byte chunks for blocks 0-2.
          - **dict** mapping block indices (0-2) to 16-byte blobs or hex strings.

        @raises ValueError: If data is an invalid size or dict contains bad block keys.
        @raises GNetPlusError: If any write fails.
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if isinstance(data, (bytes, bytearray)) and len(data) == 16:
            for block in (0, 1, 2):
                self.write_block(block, data)
            return

        if isinstance(data, (bytes, bytearray)) and len(data) == 16 * 3:
            for i, block in enumerate((0, 1, 2)):
                self.write_block(block, data[i * 16:(i + 1) * 16])
            return

        if isinstance(data, dict):
            for block, blob in data.items():
                if block not in (0, 1, 2):
                    raise ValueError(
                        f'Block key {block!r} invalid; must be 0, 1, or 2 '
                        '(block 3 is the sector trailer)'
                    )
                if isinstance(blob, str):
                    blob = bytes.fromhex(blob)
                self.write_block(block, blob)
            return

        length = len(data) if isinstance(data, (bytes, bytearray)) else 'unknown'
        raise ValueError(
            f'Unsupported data: must be 16 or 48 bytes (or equivalent hex), '
            f'or a dict of block->16-byte blobs. Got length={length!r}'
        )

    def write_sector_uniform(self, data: Union[str, bytes]) -> None:
        """Write the same 16 bytes to blocks 0, 1, *and* 2 of the authenticated sector.

        This is an explicit, intent-revealing alias for the 16-byte dispatch
        path of :meth:`write_sector`.  Use it when you deliberately want
        every data block in the sector to hold identical content (e.g. bulk
        wipe / factory-reset workflows).

        @param data: Exactly 16 bytes or a 32-character hex string.
        @raises ValueError: If *data* is not exactly 16 bytes.
        @raises GNetPlusError: If any block write fails.
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)
        if len(data) != 16:
            raise ValueError('data must be exactly 16 bytes')
        for block in (0, 1, 2):
            self.write_block(block, data)

    # ------------------------------------------------------------------
    # Multi-sector bulk read / write
    # ------------------------------------------------------------------

    def read_blocks(
        self,
        mapping: "dict[int, list[int]]",
        raw: bool = False,
        combine: bool = False,
        keys: "Optional[Union[bytes, dict[int, bytes]]]" = None,
        key_types: "Union[str, dict[int, str]]" = 'A',
        timeout: "Union[float, dict[int, float]]" = 1.0,
        flush: "Union[bool, dict[int, bool]]" = True,
        auth: "Optional[dict[int, SectorAuth]]" = None,
    ) -> "Union[dict[int, dict[int, Union[str, bytes]]], Union[str, bytes]]":
        """
        Read multiple blocks across sectors with optional per-sector authentication.

        Authentication can be supplied two ways (mutually exclusive; ``auth``
        takes precedence when both are given):

        **New style** — ``auth`` dict of :class:`~mifarepy.SectorAuth`:

        .. code-block:: python

            results = reader.read_blocks(
                {1: [0, 1], 2: [0]},
                auth={
                    1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
                    2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
                },
            )

        **Legacy style** — ``keys`` + ``key_types`` + ``timeout`` + ``flush``
        (still fully supported).

        @param mapping:   ``{sector: [block, ...]}`` blocks to read per sector.
        @param raw:       ``True`` → bytes; ``False`` → hex strings.
        @param combine:   ``True`` → concatenate all results into one value.
        @param keys:      Global 6-byte key or ``{sector: key}`` per-sector.
        @param key_types: ``'A'``/``'B'`` globally or per-sector dict.
        @param timeout:   Auth timeout globally or per-sector dict.
        @param flush:     Buffer-flush flag globally or per-sector dict.
        @param auth:      ``{sector: SectorAuth}`` — new-style per-sector auth.
        @return:          ``{sector: {block: data}}`` or combined bytes/hex string.
        @raises GNetPlusError: If authentication or any block read fails.
        """
        results: dict[int, dict[int, Union[str, bytes]]] = {}

        for sector, blocks in mapping.items():
            if auth is not None and sector in auth:
                sa = auth[sector]
                self.authenticate_sector(sector, sa.key, sa.key_type, sa.timeout, sa.flush)
            else:
                key = self._resolve_per_sector_param(keys, sector, None)
                ktype = self._resolve_per_sector_param(key_types, sector, 'A')
                ktout = self._resolve_per_sector_param(timeout, sector, 1.0)
                kflush = self._resolve_per_sector_param(flush, sector, True)
                if key is not None:
                    self.authenticate_sector(sector, key, ktype, ktout, kflush)

            results[sector] = {}
            for block in blocks:
                results[sector][block] = self.read_block(block, raw=raw)

        if combine:
            if raw:
                return b''.join(
                    results[s][b] for s, blocks in mapping.items() for b in blocks  # type: ignore[misc]
                )
            return ''.join(
                results[s][b] for s, blocks in mapping.items() for b in blocks  # type: ignore[misc]
            )

        return results

    def write_blocks(
        self,
        mapping: "dict[int, Union[bytes, str, dict[int, Union[str, bytes]]]]",
        keys: "Optional[Union[bytes, dict[int, bytes]]]" = None,
        key_types: "Union[str, dict[int, str]]" = 'A',
        timeout: "Union[float, dict[int, float]]" = 1.0,
        flush: "Union[bool, dict[int, bool]]" = True,
        auth: "Optional[dict[int, SectorAuth]]" = None,
    ) -> None:
        """
        Write multiple blocks across sectors with optional per-sector authentication.

        Authentication can be supplied two ways (mutually exclusive; ``auth``
        takes precedence when both are given):

        **New style** — ``auth`` dict of :class:`~mifarepy.SectorAuth`:

        .. code-block:: python

            reader.write_blocks(
                {1: b'\x00' * 48, 2: {0: b'\xAA' * 16}},
                auth={
                    1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
                    2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
                },
            )

        **Legacy style** — ``keys`` + ``key_types`` + ``timeout`` + ``flush``
        (still fully supported).

        @param mapping:   ``{sector: blob_or_dict}`` data to write per sector.
        @param keys:      Global 6-byte key or ``{sector: key}`` per-sector.
        @param key_types: ``'A'``/``'B'`` globally or per-sector dict.
        @param timeout:   Auth timeout globally or per-sector dict.
        @param flush:     Buffer-flush flag globally or per-sector dict.
        @param auth:      ``{sector: SectorAuth}`` — new-style per-sector auth.
        @raises ValueError:    If any block data is not exactly 16 bytes.
        @raises GNetPlusError: If authentication or any block write fails.
        """
        for sector, spec in mapping.items():
            if auth is not None and sector in auth:
                sa = auth[sector]
                self.authenticate_sector(sector, sa.key, sa.key_type, sa.timeout, sa.flush)
            else:
                key = self._resolve_per_sector_param(keys, sector, None)
                ktype = self._resolve_per_sector_param(key_types, sector, 'A')
                ktout = self._resolve_per_sector_param(timeout, sector, 1.0)
                kflush = self._resolve_per_sector_param(flush, sector, True)
                if key is not None:
                    self.authenticate_sector(sector, key, ktype, ktout, kflush)

            if isinstance(spec, dict):
                for block, data in spec.items():
                    self.write_block(block, data)
            else:
                self.write_sector(spec)
