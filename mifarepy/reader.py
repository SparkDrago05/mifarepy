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


"""High-level reader API for MIFARE readers that speak the GNetPlus® protocol.

```python
from mifarepy import MifareReader

with MifareReader('/dev/ttyUSB0') as reader:
    print('UID:', reader.get_uid())
```
"""

import asyncio
import logging
import struct
import time
import warnings
from typing import Any, Literal, Optional, Union, overload

import serial

from . import layout
from .protocol import CardInfo, GNetPlusError, InvalidMessage, QueryMessage, ResponseMessage, SectorAuth

logger = logging.getLogger(__name__)

#: Operation codes for the SET_VALUE / SET_VALUEEX commands.
VALUE_INCREMENT = 0xC1
VALUE_DECREMENT = 0xC0

#: NAK codes meaning "this reader does not implement that command".
_UNSUPPORTED_COMMAND_NAKS = frozenset({0xE1, 0xE6})

ValueOps = Literal['auto', 'native', 'software']


class MifareReader:
    """
    Class for interfacing with the RFID card reader.

    Can be used as a context manager to ensure the serial port is closed:

    ```python
    with MifareReader('/dev/ttyUSB0') as reader:
        uid = reader.get_sn()
    ```
    """

    def __init__(
        self,
        port: str = '/dev/ttyUSB0',
        baudrate: int = 19200,
        deviceaddr: int = 0,
        *,
        value_ops: ValueOps = 'auto',
        **kwargs: Any,
    ) -> None:
        """
        Initialize the RFID reader connection.

        Args:
            port: Serial port name (e.g., '/dev/ttyUSB0').
            baudrate: Baudrate for interfacing with the device. Don't change this unless you know what you're doing.
            deviceaddr: Device address (default: 0).
            value_ops: How value-block arithmetic is performed.
                ``'auto'`` (default) increments and decrements by
                read-modify-write, and uses the native RESTORE / TRANSFER
                commands for `transfer()` / `restore()`, verifying the result
                and falling back to read-modify-write if they fail.
                ``'native'`` uses only the native commands, including
                SET_VALUE for increment/decrement; ``'software'`` uses only
                read-modify-write (the behaviour before 3.1).
            **kwargs: Extra keyword arguments passed to `serial.Serial`.

        Raises:
            RuntimeError: If the serial port cannot be opened.
        """
        if value_ops not in ('auto', 'native', 'software'):
            raise ValueError("value_ops must be 'auto', 'native' or 'software'")
        self.port = port
        self.baudrate = baudrate
        self.deviceaddr = deviceaddr
        self.value_ops: ValueOps = value_ops
        # None = not yet known; True/False once the reader has shown whether
        # native value commands work.
        self._native_values_ok: Optional[bool] = None
        # Sector and key type of the most recent successful authentication.
        self._auth_sector: Optional[int] = None
        self._auth_key_type: Literal['A', 'B'] = 'A'

        try:
            self.serial = serial.Serial(port, baudrate=baudrate, **kwargs)
        except serial.SerialException as pe:
            raise RuntimeError(f'Unable to open port {port}: {pe}') from pe

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Reset auto mode then close the underlying serial port.

        Disabling auto mode before closing ensures the reader is left in a
        clean, command-driven state so the next session does not receive
        spurious EVN events or NAK responses from a lingering event mode.
        """
        if hasattr(self, 'serial') and getattr(self.serial, 'is_open', False):
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
        state = 'open' if (hasattr(self, 'serial') and getattr(self.serial, 'is_open', False)) else 'closed'
        return f'MifareReader(port={self.port!r}, baudrate={self.baudrate}, addr={self.deviceaddr}, {state})'

    # ------------------------------------------------------------------
    # Low-level send / receive
    # ------------------------------------------------------------------

    def sendmsg(self, function: int, data: bytes = b'') -> None:
        """
        Construct and send a QueryMessage to the RFID reader.

        Args:
            function: @see Message.function
            data: @see Message.data
        """
        QueryMessage(self.deviceaddr, function, data).sendto(self.serial)

    def readmsg(self, sink_events: bool = False) -> ResponseMessage:
        """
        Read a message, optionally ignoring EVN (event) messages which are
        device-driven.

        Args:
            sink_events: If True, silently discard EVN messages.

        Returns:
            Constructed ResponseMessage instance.

        Raises:
            GNetPlusError: If a NAK response is received.
        """
        while True:
            response = ResponseMessage.readfrom(self.serial)

            if sink_events and response.function == ResponseMessage.EVN:
                continue

            break

        error = response.to_error()
        if error is not None:
            raise error

        return response

    def _resolve_per_sector_param(self, param, sector, default):
        """
        Resolve a parameter that can be either a scalar (applied to all sectors)
        or a dict mapping sector number to a per-sector value.

        Args:
            param: Scalar value or dict[sector -> value].
            sector: Current sector number being processed.
            default: Fallback if param is None or sector not in dict.

        Returns:
            Resolved value for this sector.
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

        Unlike `_detect_card_uid()`, this wakes HALT-state cards too.
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
        Get the serial number of the card currently in the RF field.

        Warning: Deprecated
            Use `get_uid()` (returns ``'0xAABBCCDD'`` string) or
            `get_uid_int()` (returns unsigned integer) instead.

        Args:
            endian: ``'big'`` or ``'little'``.  Selects byte order for the
                4-byte UID from the ANTI_COLLISION response.
            as_string: If ``True`` returns ``'0xAABBCCDD'`` hex string;
                otherwise an unsigned integer.

        Returns:
            Card UID as hex string or integer.
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
        use `scan_tag()` or `select_card()` when you need the card
        to be in an active/authenticated state.

        Returns:
            UID string like ``'0xAABBCCDD'``.

        Raises:
            GNetPlusError: If no card is present or the reader returns NAK.
        """
        uid_bytes = self._detect_card_uid()
        uid = struct.unpack('<L', uid_bytes)[0]
        return f'0x{uid:08X}'

    def get_uid_int(self) -> int:
        """
        Return the 4-byte UID of the card currently in the RF field as an
        unsigned 32-bit integer (little-endian byte order).

        Returns:
            Unsigned 32-bit UID integer.

        Raises:
            GNetPlusError: If no card is present or the reader returns NAK.
        """
        uid_bytes = self._detect_card_uid()
        return struct.unpack('<L', uid_bytes)[0]

    def request_all(self, endian: str = 'little', as_string: bool = True) -> Union[str, int]:
        """
        Enumerate *all* cards in field (REQUEST_ALL + ANTI_COLLISION), including
        cards in HALT state.  Useful for multi-card scanning.

        Args:
            endian: ``'big'`` or ``'little'`` byte order for the 4-byte UID.
            as_string: If ``True`` returns hex string; otherwise integer.

        Returns:
            Card UID as hex string or integer.
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

        Args:
            as_string: If ``True`` returns hex string; otherwise raw bytes.

        Returns:
            Secondary serial number as hex string or bytes.
        """
        self.sendmsg(QueryMessage.GET_SECOND_SN)
        response = self.readmsg()
        return response.data.hex() if as_string else response.data

    def select_card(self) -> bytes:
        """
        Run REQUEST → ANTI_COLLISION → SELECT_CARD to bring a card into
        the active state ready for authentication and block operations.

        Called automatically by `authenticate_sector()` before every
        key-load / authenticate sequence, so you normally do not need to
        call this directly.  It is still public for advanced multi-card
        workflows (see example 08).

        Returns:
            ACK payload bytes from the SELECT_CARD response.

        Raises:
            GNetPlusError: If any step returns a NAK.
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

        Returns:
            ``True`` if the reader acknowledged the POLLING command.

        Raises:
            GNetPlusError: If the reader explicitly NAKs (unusual).
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

        Does **not** select or authenticate the card — use `scan_tag()`
        or `select_card()` for that.

        Returns:
            ``True`` if a card is in the RF field, ``False`` otherwise.
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

        Returns a `CardInfo` dataclass with the
        UID available in multiple representations.  The card is left in
        the *active* state so you can immediately call
        `authenticate_sector()` / `read_block()` etc.

        Usage example:

        ```python
        card = reader.scan_tag()
        print(card)            # '0xEDCEF8C3'
        print(card.uid_int)    # 3989956803
        ```

        Returns:
            `CardInfo` with ``uid``, ``uid_int``, and ``uid_bytes``.

        Raises:
            GNetPlusError: If no card is present or any step fails.
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

    def wait_for_card(self, timeout: float = 10.0) -> str:
        """
        Check if a card is already present; if not, wait for a card-insert event.

        Args:
            timeout: Maximum time to wait in seconds (default: 10).

        Returns:
            Card serial number string.

        Raises:
            TimeoutError: If no card is detected within the timeout.
        """
        try:
            card_sn = self.get_uid()
            if card_sn:
                logger.info('Card already present: %s', card_sn)
                return card_sn
        except GNetPlusError:
            pass  # No card yet; wait for EVN

        # Enable events only after the presence check: on PGM0487 V1.4R0 a
        # REQUEST that finds no card stops EVN events until auto mode is set
        # again. A card that arrived in between is reported as soon as auto
        # mode is enabled.
        self.set_auto_mode()

        # Bound every read by the time left, otherwise a blocking serial port
        # (timeout=None, the default) waits for an event forever.
        deadline = time.monotonic() + timeout
        orig_timeout = getattr(self.serial, 'timeout', None)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.serial.timeout = remaining
                try:
                    response = self.readmsg()
                except InvalidMessage:
                    continue  # read timed out (or a partial frame); re-check the deadline
                if (response.function == ResponseMessage.EVN
                        and ResponseMessage.EVN_CARD_IN in response.data):
                    logger.info('Card insertion event received')
                    self.serial.timeout = orig_timeout
                    return self.get_uid()
        finally:
            self.serial.timeout = orig_timeout

        raise TimeoutError('No card detected within the time limit')

    async def wait_for_card_async(self, timeout: float = 10.0) -> str:
        """
        Async variant of ``wait_for_card``. Does not block the event loop —
        serial I/O runs in a thread-pool executor.

        Suitable for use inside ``asyncio``-based applications (FastAPI,
        Django async views, automation scripts using ``asyncio.run``).

        Usage example:

        ```python
        import asyncio
        from mifarepy import MifareReader

        async def main():
            with MifareReader('/dev/ttyUSB0') as reader:
                uid = await reader.wait_for_card_async(timeout=15)
                print('Card:', uid)

        asyncio.run(main())
        ```

        Args:
            timeout: Maximum seconds to wait (default: 10).

        Returns:
            Card UID as hex string.

        Raises:
            TimeoutError: If no card is detected within the timeout.
        """
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: self.wait_for_card(timeout)),
            timeout=timeout + 1,  # give the inner timeout a chance to fire first
        )

    # ------------------------------------------------------------------
    # Reader control
    # ------------------------------------------------------------------

    def get_version(self) -> str:
        """
        Get product version string.

        Returns:
            Firmware/hardware version string from the connected reader.
        """
        self.sendmsg(QueryMessage.GET_VERSION)
        response = self.readmsg().data
        # PGM0487 firmware pads the string with a trailing NUL.
        return response.decode('latin1', errors='ignore').strip('\x00 \t\r\n')

    def set_auto_mode(self, enabled: bool = True) -> bytes:
        """
        Toggle auto mode — whether the device emits EVN events when a card enters field.

        Args:
            enabled: True to enable, False to disable.

        Returns:
            Confirmed mode byte from the device.

        Raises:
            GNetPlusError: If the device reports failure to set the mode.
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

        Raises:
            GNetPlusError: If the reader returns a NAK.
        """
        self.sendmsg(QueryMessage.HALT)
        self.readmsg()

    def rf_power(self, on: bool) -> None:
        """
        Switch the RF field power on or off.

        Turning the RF field off and back on can reset cards that are in an
        inconsistent state without physically removing them.

        Args:
            on: True to power on the RF field, False to power it off.

        Raises:
            GNetPlusError: If the reader returns a NAK.
        """
        self.sendmsg(QueryMessage.RF_POWER_ONOFF, b'\x01' if on else b'\x00')
        self.readmsg()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate_sector(
        self,
        sector: int,
        key: bytes,
        key_type: str = 'A',
        timeout: float = 1.0,
        flush: bool = True,
    ) -> None:
        """
        Load a key into the reader and authenticate the specified MIFARE Classic sector.

        Args:
            sector: Sector number to authenticate (0-15 for 1K; 0-39 for 4K).
            key: 6-byte authentication key.
            key_type: 'A' for Key A (0x60) or 'B' for Key B (0x61).
            timeout: Timeout in seconds for reader responses.
            flush: Whether to flush the input buffer before reading responses.

        Raises:
            ValueError: If key_type is invalid or key length is not 6 bytes.
            GNetPlusError: If the reader returns NAK during key load or authentication.
        """
        if key_type not in ('A', 'B'):
            raise ValueError("key_type must be 'A' or 'B'")
        if len(key) != 6:
            raise ValueError('key must be exactly 6 bytes long')

        # Re-select the card so this call is safe after any write operation.
        # MIFARE cards fall back to IDLE after writes; without SELECT they will
        # refuse the subsequent AUTHENTICATE with NAK 0x04 (authenticate error).
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
        self._remember_auth(sector, key_type)

    def authenticate_sector_cached(
        self,
        sector: int,
        key_type: Literal['A', 'B'] = 'A',
        timeout: float = 1.0,
    ) -> None:
        """Authenticate a sector using a key that is **already loaded** in the reader.

        Skips the SAVE_KEY step (opcode 0x2B) and jumps straight to
        AUTHENTICATE_KEY (opcode 0x2E).  This is faster when the same key
        has already been loaded by a previous `authenticate_sector()` call
        in the same session.

        Warning:
            The reader only stores **one** key internally.  If any other sector
            was authenticated (or the reader was reset) since the last
            SAVE_KEY, call `authenticate_sector()` instead.

        Args:
            sector: Sector to authenticate (0-15 for 1K; 0-39 for 4K).
            key_type: ``'A'`` for Key A (0x60) or ``'B'`` for Key B (0x61).
            timeout: Timeout in seconds for the reader response.

        Raises:
            ValueError: If ``key_type`` is invalid.
            GNetPlusError: If the reader returns NAK.
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
        self._remember_auth(sector, key_type)

    def _remember_auth(self, sector: int, key_type: str) -> None:
        self._auth_sector = sector
        self._auth_key_type = 'B' if key_type == 'B' else 'A'

    def _sector_or_current(self, sector: Optional[int]) -> Optional[int]:
        """Return *sector* if given, else the most recently authenticated sector."""
        return sector if sector is not None else self._auth_sector

    def _data_blocks(self, sector: Optional[int]) -> range:
        """Relative data-block numbers for *sector* (3 blocks when unknown)."""
        target = self._sector_or_current(sector)
        return layout.data_blocks(target) if target is not None else range(3)

    @overload
    def read_block(self, block: int, raw: Literal[True]) -> bytes: ...
    @overload
    def read_block(self, block: int, raw: Literal[False] = ...) -> str: ...
    @overload
    def read_block(self, block: int, raw: bool = ...) -> Union[bytes, str]: ...
    def read_block(self, block: int, raw: bool = False) -> Union[bytes, str]:
        """
        Read a single 16-byte block from the currently authenticated sector.

        Args:
            block: Block index relative to the authenticated sector (0-3).
            raw: If True returns bytes; if False returns hex string.

        Returns:
            Block data as bytes (raw=True) or hex string (raw=False).

        Raises:
            GNetPlusError: If the read fails.
        """
        self.sendmsg(QueryMessage.READ_BLOCK, bytes([block]))
        response = self.readmsg()
        return response.data if raw else response.data.hex()

    def write_block(self, block: int, data: "Union[str, bytes]") -> str:
        """
        Write a 16-byte block to the currently authenticated sector.

        Args:
            block: Block index relative to the authenticated sector (0-3).
            data: Data to write -- exactly 16 bytes or a 32-character hex string.

        Returns:
            Reader's echoed data in hex format.

        Raises:
            ValueError: If data is not exactly 16 bytes.
            GNetPlusError: If the write fails.
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

        Args:
            block: Block index relative to the authenticated sector (0-2).

        Returns:
            Signed 32-bit integer stored in the value block.

        Raises:
            GNetPlusError: If the read fails.
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

        Args:
            block: Block index relative to the authenticated sector (0-2).
            value: Signed 32-bit integer to store.

        Raises:
            ValueError: If value is outside signed 32-bit range.
            GNetPlusError: If the write fails.
        """
        if not (-2**31 <= value <= 2**31 - 1):
            raise ValueError('value must be a signed 32-bit integer')
        self.create_value_block(block, value)

    def create_value_block(self, block: int, initial_value: int = 0) -> None:
        """
        Initialize a block as a MIFARE value block with the GNetPlus redundant
        format (value stored three times: twice normal, once inverted).

        Must authenticate the sector before calling.

        Args:
            block: Block index relative to the authenticated sector (0-2).
            initial_value: Signed 32-bit starting value (default: 0).

        Raises:
            ValueError: If initial_value is outside signed 32-bit range.
            GNetPlusError: If the operation fails.
        """
        if not (-2**31 <= initial_value <= 2**31 - 1):
            raise ValueError('initial_value must be a signed 32-bit integer')
        payload = bytes([block]) + struct.pack('<i', initial_value)
        self.sendmsg(QueryMessage.CREATE_VALUE_BLOCK, payload)
        self.readmsg()

    # ------------------------------------------------------------------
    # Value-block arithmetic: native commands with verification + fallback
    # ------------------------------------------------------------------

    def _use_native_values(self) -> bool:
        if self.value_ops == 'software':
            return False
        if self.value_ops == 'native':
            return True
        return self._native_values_ok is not False

    def _recover_after_nak(self) -> None:
        """Re-authenticate after a failed native command (the card drops to IDLE)."""
        if self._auth_sector is None:
            raise RuntimeError(
                'Cannot fall back to read-modify-write: no sector has been authenticated '
                'on this reader yet. Call authenticate_sector() first.'
            )
        self.authenticate_sector_cached(self._auth_sector, self._auth_key_type)

    def _run_native(self, commands: "list[tuple[int, bytes]]") -> Optional[GNetPlusError]:
        """Send native value commands. Returns the NAK raised, or None on success."""
        try:
            for function, payload in commands:
                self.sendmsg(function, payload)
                self.readmsg()
        except GNetPlusError as err:
            return err
        return None

    def _value_operation(
        self,
        block: int,
        expected: int,
        commands: "list[tuple[int, bytes]]",
        verify_block: Optional[int] = None,
    ) -> None:
        """Apply *commands* natively, verify *verify_block* holds *expected*, else fall back.

        The fallback writes *expected* with CREATE_VALUE_BLOCK, which is how
        mifarepy performed value arithmetic before native support existed.
        """
        target = block if verify_block is None else verify_block
        if not self._use_native_values():
            self.write_value(target, expected)
            return

        err = self._run_native(commands)
        if err is not None:
            if self.value_ops == 'native':
                raise err
            if err.nak_code in _UNSUPPORTED_COMMAND_NAKS:
                self._native_values_ok = False
                logger.info('Reader does not support native value commands; using read-modify-write')
            else:
                logger.debug('Native value command failed (%s); retrying as read-modify-write', err)
            self._recover_after_nak()
            self.write_value(target, expected)
            return

        actual = self.read_value(target)
        if actual == expected:
            self._native_values_ok = True
            return

        message = (
            f'Native value command left block {target} at {actual}, expected {expected}'
        )
        if self.value_ops == 'native':
            raise GNetPlusError(message)
        logger.warning('%s; correcting it and switching to read-modify-write', message)
        self._native_values_ok = False
        self.write_value(target, expected)

    @staticmethod
    def _check_delta(delta: int) -> None:
        if delta <= 0 or delta > 2**31 - 1:
            raise ValueError('delta must be a positive 32-bit integer')

    def _set_value(self, block: int, op: int, delta: int, expected: int) -> None:
        """Increment/decrement *block* by *delta*, leaving it at *expected*."""
        # SET_VALUE is only sent when value_ops='native'. PGM0487 V1.4R0
        # firmware masks bit 7 of every delta byte and drops carries, so a
        # wrong value would sit on the card until read-back corrected it.
        if self.value_ops != 'native':
            self.write_value(block, expected)
            return
        payload = bytes([block, op]) + struct.pack('<i', delta)
        self._value_operation(block, expected, [(QueryMessage.SET_VALUE, payload)])

    def increment_value(self, block: int, delta: int) -> None:
        """
        Add *delta* to a MIFARE value block.

        Reads the current value and writes the new one (read-modify-write).
        With ``value_ops='native'`` the reader's SET_VALUE command
        (increment + transfer) is sent instead and the result is read back
        to confirm it; a NAK or a wrong result raises `GNetPlusError`.

        Args:
            block: Block index relative to the authenticated sector.
            delta: Positive integer amount to add.

        Raises:
            ValueError: If delta ≤ 0 or if the result overflows int32.
            GNetPlusError: If the reader returns a NAK.
        """
        self._check_delta(delta)
        current = self.read_value(block)
        new_val = current + delta
        if new_val > 2**31 - 1:
            raise ValueError(
                f'Increment overflows signed 32-bit range: {current} + {delta} = {new_val}'
            )
        self._set_value(block, VALUE_INCREMENT, delta, new_val)

    def decrement_value(self, block: int, delta: int) -> None:
        """
        Subtract *delta* from a MIFARE value block.

        Reads the current value and writes the new one (read-modify-write),
        so the block's access conditions must allow writing. With
        ``value_ops='native'`` the reader's SET_VALUE command (decrement +
        transfer) is sent instead, which also works on decrement-only blocks
        (for example prepaid balances) if your reader's firmware computes it
        correctly; see `increment_value()`.

        Args:
            block: Block index relative to the authenticated sector.
            delta: Positive integer amount to subtract.

        Raises:
            ValueError: If delta ≤ 0 or if the result underflows int32.
            GNetPlusError: If the reader returns a NAK.
        """
        self._check_delta(delta)
        current = self.read_value(block)
        new_val = current - delta
        if new_val < -2**31:
            raise ValueError(
                f'Decrement underflows signed 32-bit range: {current} - {delta} = {new_val}'
            )
        self._set_value(block, VALUE_DECREMENT, delta, new_val)

    def transfer(self, source_block: int, dest_block: int) -> None:
        """
        Copy the value in *source_block* to *dest_block*.

        Uses the card's RESTORE (load source into the transfer buffer) and
        TRANSFER (write buffer to destination) commands, then verifies the
        destination. Both blocks must be value blocks in the authenticated
        sector.

        Args:
            source_block: Value block to copy from.
            dest_block: Value block to copy to.

        Raises:
            GNetPlusError: If either block cannot be read or written.
        """
        value = self.read_value(source_block)
        self._value_operation(
            source_block,
            value,
            [
                (QueryMessage.RESTORE, bytes([source_block])),
                (QueryMessage.TRANSFER, bytes([dest_block])),
            ],
            verify_block=dest_block,
        )

    def restore(self, block: int) -> None:
        """
        Re-commit a value block: RESTORE it into the transfer buffer and
        TRANSFER it back, rewriting the block in valid value format.

        Useful to repair a value block after an interrupted operation, as long
        as its value can still be read.

        Args:
            block: Value block relative to the authenticated sector.

        Raises:
            GNetPlusError: If the reader returns a NAK.
        """
        value = self.read_value(block)
        self._value_operation(
            block,
            value,
            [
                (QueryMessage.RESTORE, bytes([block])),
                (QueryMessage.TRANSFER, bytes([block])),
            ],
        )

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
        Read every data block of the authenticated sector (the trailer is skipped).

        That is blocks 0-2 for sectors 0-31, and blocks 0-14 for the large
        sectors 32-39 of a MIFARE Classic 4K card.

        Authenticate the sector with ``authenticate_sector`` before calling this.

        Args:
            sector: Sector whose layout to use. Defaults to the sector most
                recently authenticated on this reader (or a 4-block sector if
                none has been). It does not authenticate for you.
            raw: If True returns bytes; otherwise hex strings.
            combine: If True concatenates all data blocks into a single value.

        Returns:
            Dict mapping relative block index to data, or the combined value.

        Raises:
            GNetPlusError: If any block read fails.
        """
        results: dict[int, Union[str, bytes]] = {}

        for block in self._data_blocks(sector):
            results[block] = self.read_block(block, raw=raw)

        if combine:
            return b''.join(results.values()) if raw else ''.join(results.values())  # type: ignore[arg-type]

        return results

    def write_sector(
        self,
        data: "Union[str, bytes, dict[int, Union[str, bytes]]]",
        sector: "Optional[int]" = None,
    ) -> None:
        """
        Write data blocks of the authenticated sector. The trailer is never written.

        Supported data shapes (*n* = number of data blocks: 3, or 15 for 4K sectors 32-39):
          - **16 bytes** / **32-char hex** -- the same blob written to every data block.
          - **16 × k bytes** (k ≤ *n*) -- split into 16-byte chunks for blocks 0 … k-1.
          - **dict** mapping data-block indices to 16-byte blobs or hex strings.

        Args:
            data: The data to write, in one of the shapes above.
            sector: Sector whose layout to use. Defaults to the most recently
                authenticated sector.

        Raises:
            ValueError: If data is an invalid size or a dict key is not a data block.
            GNetPlusError: If any write fails.
        """
        blocks = self._data_blocks(sector)

        if isinstance(data, str):
            data = bytes.fromhex(data)

        if isinstance(data, dict):
            for block in data:
                if block not in blocks:
                    raise ValueError(
                        f'Block key {block!r} invalid; must be {blocks.start}-{blocks.stop - 1} '
                        f'(block {blocks.stop} is the sector trailer)'
                    )
            for block, blob in data.items():
                if isinstance(blob, str):
                    blob = bytes.fromhex(blob)
                self.write_block(block, blob)
            return

        if isinstance(data, (bytes, bytearray)) and len(data) == 16:
            for block in blocks:
                self.write_block(block, data)
            return

        if (isinstance(data, (bytes, bytearray)) and data
                and len(data) % 16 == 0 and len(data) // 16 <= len(blocks)):
            for i in range(len(data) // 16):
                self.write_block(blocks[i], data[i * 16:(i + 1) * 16])
            return

        length = len(data) if isinstance(data, (bytes, bytearray)) else 'unknown'
        raise ValueError(
            f'Unsupported data: must be 16 bytes or a multiple of 16 up to {16 * len(blocks)} bytes '
            f'(or equivalent hex), or a dict of block->16-byte blobs. Got length={length!r}'
        )

    def write_sector_uniform(self, data: Union[str, bytes], sector: "Optional[int]" = None) -> None:
        """Write the same 16 bytes to every data block of the authenticated sector.

        This is an explicit, intent-revealing alias for the 16-byte dispatch
        path of `write_sector()`. Use it when you deliberately want every
        data block in the sector to hold identical content (e.g. bulk wipe /
        factory-reset workflows).

        Args:
            data: Exactly 16 bytes or a 32-character hex string.
            sector: Sector whose layout to use. Defaults to the most recently
                authenticated sector.

        Raises:
            ValueError: If *data* is not exactly 16 bytes.
            GNetPlusError: If any block write fails.
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)
        if len(data) != 16:
            raise ValueError('data must be exactly 16 bytes')
        for block in self._data_blocks(sector):
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

        **New style** — ``auth`` dict of `SectorAuth`:

        ```python
        results = reader.read_blocks(
            {1: [0, 1], 2: [0]},
            auth={
                1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
                2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
            },
        )
        ```

        **Legacy style** — ``keys`` + ``key_types`` + ``timeout`` + ``flush``
        (still fully supported).

        Args:
            mapping: ``{sector: [block, ...]}`` blocks to read per sector.
            raw: ``True`` → bytes; ``False`` → hex strings.
            combine: ``True`` → concatenate all results into one value.
            keys: Global 6-byte key or ``{sector: key}`` per-sector.
            key_types: ``'A'``/``'B'`` globally or per-sector dict.
            timeout: Auth timeout globally or per-sector dict.
            flush: Buffer-flush flag globally or per-sector dict.
            auth: ``{sector: SectorAuth}`` — new-style per-sector auth.

        Returns:
            ``{sector: {block: data}}`` or combined bytes/hex string.

        Raises:
            GNetPlusError: If authentication or any block read fails.
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

        **New style** — ``auth`` dict of `SectorAuth`:

        ```python
        reader.write_blocks(
            {1: b'\x00' * 48, 2: {0: b'\xAA' * 16}},
            auth={
                1: SectorAuth(key=bytes.fromhex('FFFFFFFFFFFF')),
                2: SectorAuth(key=bytes.fromhex('A0A1A2A3A4A5'), key_type='B'),
            },
        )
        ```

        **Legacy style** — ``keys`` + ``key_types`` + ``timeout`` + ``flush``
        (still fully supported).

        Args:
            mapping: ``{sector: blob_or_dict}`` data to write per sector.
            keys: Global 6-byte key or ``{sector: key}`` per-sector.
            key_types: ``'A'``/``'B'`` globally or per-sector dict.
            timeout: Auth timeout globally or per-sector dict.
            flush: Buffer-flush flag globally or per-sector dict.
            auth: ``{sector: SectorAuth}`` — new-style per-sector auth.

        Raises:
            ValueError: If any block data is not exactly 16 bytes.
            GNetPlusError: If authentication or any block write fails.
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
                self.write_sector(spec, sector=sector)
