import pytest
import struct
import warnings
from mifarepy.protocol import (
    gencrc,
    Message,
    QueryMessage,
    ResponseMessage,
    InvalidMessage,
    GNetPlusError,
    SectorAuth,
    CardInfo,
)
from mifarepy import MifareReader
import serial


# --- Helpers for building fake serial interactions ---
class DummySerial:
    def __init__(self, to_read: bytes):
        self._to_read = to_read
        self.written = b''
        self.timeout = None

    def write(self, data: bytes):
        self.written += data

    def read(self, n: int) -> bytes:
        chunk = self._to_read[:n]
        self._to_read = self._to_read[n:]
        return chunk

    def reset_input_buffer(self):
        pass


def build_response(address: int, func: int, data: bytes) -> bytes:
    # Build a ResponseMessage bytes with CRC
    body = struct.pack('BBB', address, func, len(data)) + data
    crc = gencrc(body)
    return bytes([Message.SOH]) + body + struct.pack('>H', crc)


# --- Protocol Tests ---
def test_gencrc_empty():
    # CRC of no data should equal preset 0xFFFF
    assert gencrc(b'') == 0xFFFF


def test_message_roundtrip():
    # Message packing and unpacking
    msg = Message(0x02, 0x05, b"\xAA\xBB")
    raw = bytes(msg)
    # Simulate reading from serial
    ser = DummySerial(raw)
    parsed = Message.readfrom(ser)
    assert parsed.address == msg.address
    assert parsed.function == msg.function
    assert parsed.data == msg.data


def test_message_incomplete_header():
    ser = DummySerial(b'\x01\x02')
    with pytest.raises(InvalidMessage):
        Message.readfrom(ser)


def test_message_crc_mismatch():
    # valid header but bad CRC
    body = struct.pack('BBB', 0, 1, 1) + b'X'
    fake = bytes([Message.SOH]) + body + b'\x00\x00'
    ser = DummySerial(fake)
    with pytest.raises(InvalidMessage):
        Message.readfrom(ser)


def test_query_message_constants():
    assert QueryMessage.REQUEST == 0x20
    assert QueryMessage.GET_VERSION == 0x01


def test_response_to_error_and_ack():
    # NAK response should convert to error with code_description populated
    err = ResponseMessage(0, ResponseMessage.NAK, b'err')
    exc = err.to_error()
    assert isinstance(exc, GNetPlusError)
    assert exc.raw == b'err'
    assert isinstance(exc.code_description, str)
    # ACK response should not be error
    ack = ResponseMessage(0, ResponseMessage.ACK, b'')
    assert ack.to_error() is None


def test_gnetplus_error_known_nak_code():
    # b'\x05' maps to 'Authentication failed'
    err = ResponseMessage(0, ResponseMessage.NAK, b'\x05')
    exc = err.to_error()
    assert exc.code_description == 'Authentication failed'
    assert 'Authentication failed' in str(exc)


def test_evn_card_in_constant():
    assert ResponseMessage.EVN_CARD_IN == b'I'


# --- Reader Tests ---
@pytest.fixture(autouse=True)
def patch_serial(monkeypatch):
    # By default, serial.Serial returns a DummySerial; overwritten per-test
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: DummySerial(b''))


def test_init_failure(monkeypatch):
    class BadSerialExc(Exception): pass

    # Simulate SerialException
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: (_ for _ in ()).throw(serial.SerialException('fail')))
    with pytest.raises(RuntimeError):
        MifareReader('/dev/fake')


def test_get_version(monkeypatch):
    # Fake version string 'v1.2' in response
    resp = build_response(0, ResponseMessage.ACK, b'v1.2')
    dummy = DummySerial(resp)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader('/dev/ttyUSB0')
    ver = r.get_version()
    assert ver == 'v1.2'
    # Ensure correct command was sent
    sent = dummy.written
    assert bytes([Message.SOH, 0, QueryMessage.GET_VERSION, 0]) in sent


def test_set_auto_mode_success(monkeypatch):
    # Expect mode byte 0x01 back
    resp = build_response(0, ResponseMessage.ACK, b'\x01')
    dummy = DummySerial(resp)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    out = r.set_auto_mode(True)
    assert out == b'\x01'


def test_get_sn(monkeypatch):
    # Simulate two responses: one for REQUEST, one for ANTI_COLLISION
    uid_val = 0x11223344
    # First: dummy ACK
    resp1 = build_response(0, ResponseMessage.ACK, b'')
    # Second: return LE-packed UID
    resp2 = build_response(0, ResponseMessage.ACK, struct.pack('<L', uid_val))
    dummy = DummySerial(resp1 + resp2)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    # get_sn is deprecated — ensure it still works but warns
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        sn = r.get_sn(endian='little', as_string=True)
    assert sn == '0x11223344'
    assert any(issubclass(warning.category, DeprecationWarning) for warning in w)


def test_read_block_and_write_block(monkeypatch):
    # Simulate read_block returning 16 bytes of 0xAB
    data = b'\xAB' * 16
    resp_read = build_response(0, ResponseMessage.ACK, data)
    dummy = DummySerial(resp_read)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    out_hex = r.read_block(5, raw=False)
    assert isinstance(out_hex, str) and len(out_hex) == 32
    # Now test write_block; simulate ACK
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    dummy2 = DummySerial(resp_write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy2)
    r2 = MifareReader()
    # valid write — write_block now returns str
    result = r2.write_block(3, b'A' * 16)
    assert isinstance(result, str) and result == ''  # empty ACK payload -> empty hex string
    # invalid length
    with pytest.raises(ValueError):
        r2.write_block(1, b'short')


def test_read_and_write_sector(monkeypatch):
    # read_sector reads 3 data blocks (0, 1, 2); block 3 is the trailer and is skipped
    blocks = [build_response(0, ResponseMessage.ACK, b'\x00' * 16) for _ in range(3)]
    dummy = DummySerial(b''.join(blocks))
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    sec = r.read_sector(sector=1)
    assert isinstance(sec, dict) and len(sec) == 3
    assert set(sec.keys()) == {0, 1, 2}
    # write_sector single blob should call write_block 3 times
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy2 = DummySerial(resp_ack * 3)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy2)
    r2 = MifareReader()
    r2.write_sector(b'\x11' * 16)
    assert dummy2.written.count(QueryMessage.WRITE_BLOCK.to_bytes(1, 'little')) == 3


def test_authenticate_sector_invalid_type():
    r = MifareReader()
    with pytest.raises(ValueError):
        r.authenticate_sector(1, b'\x00' * 6, key_type='C')


def test_authenticate_sector_invalid_length():
    r = MifareReader()
    with pytest.raises(ValueError):
        r.authenticate_sector(1, b'\x00' * 5, key_type='A')


def test_authenticate_sector_nak_on_save_key(monkeypatch):
    # authenticate_sector calls select_card() internally; prepend 3 select responses
    resp_req  = build_response(0, ResponseMessage.ACK, b'')
    resp_anti = build_response(0, ResponseMessage.ACK, b'\x00\x00\x00\x00')
    resp_sel  = build_response(0, ResponseMessage.ACK, b'')
    resp_nak  = build_response(0, ResponseMessage.NAK, b'badkey')
    dummy = DummySerial(resp_req + resp_anti + resp_sel + resp_nak)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(GNetPlusError):
        r.authenticate_sector(0, b'\x01\x02\x03\x04\x05\x06', key_type='A')


def test_authenticate_sector_nak_on_auth(monkeypatch):
    # select ACK responses, then SAVE_KEY ACK, then AUTHENTICATE NAK
    resp_req  = build_response(0, ResponseMessage.ACK, b'')
    resp_anti = build_response(0, ResponseMessage.ACK, b'\x00\x00\x00\x00')
    resp_sel  = build_response(0, ResponseMessage.ACK, b'')
    resp_ack  = build_response(0, ResponseMessage.ACK, b'')
    resp_nak  = build_response(0, ResponseMessage.NAK, b'failauth')
    dummy = DummySerial(resp_req + resp_anti + resp_sel + resp_ack + resp_nak)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(GNetPlusError):
        r.authenticate_sector(0, b'\x01\x02\x03\x04\x05\x06', key_type='B')


def test_write_sector_dict_variant(monkeypatch):
    data_map = {0: b'\xAA' * 16, 2: b'\xBB' * 16}
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack * 2)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.write_sector(data_map)
    write_byte = bytes([QueryMessage.WRITE_BLOCK])
    assert dummy.written.count(write_byte) == 2


def test_write_sector_invalid_block_key(monkeypatch):
    # Block key 3 is the sector trailer — must be rejected
    dummy = DummySerial(b'')
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError, match='sector trailer'):
        r.write_sector({3: b'\xFF' * 16})


def test_context_manager(monkeypatch):
    closed = []

    class TrackingSerial(DummySerial):
        def isOpen(self):
            return True
        def close(self):
            closed.append(True)

    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: TrackingSerial(b''))
    with MifareReader('/dev/ttyUSB0') as r:
        assert isinstance(r, MifareReader)
    assert closed, 'Serial port was not closed on context manager exit'


def test_halt(monkeypatch):
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.halt()  # Should not raise
    assert bytes([QueryMessage.HALT]) in dummy.written


def test_rf_power(monkeypatch):
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.rf_power(False)
    assert bytes([QueryMessage.RF_POWER_ONOFF]) in dummy.written


def test_read_value(monkeypatch):
    # Signed int 42 packed as little-endian 32-bit
    import struct
    val_bytes = struct.pack('<i', 42)
    resp = build_response(0, ResponseMessage.ACK, val_bytes)
    dummy = DummySerial(resp)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    result = r.read_value(0)
    assert result == 42


def test_write_value(monkeypatch):
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.write_value(0, -100)  # Should not raise
    # write_value delegates to create_value_block (CREATE_VALUE_BLOCK command)
    assert bytes([QueryMessage.CREATE_VALUE_BLOCK]) in dummy.written


def test_write_value_out_of_range(monkeypatch):
    dummy = DummySerial(b'')
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError):
        r.write_value(0, 2**32)  # beyond signed 32-bit


def test_authenticate_sector_calls_select_card(monkeypatch):
    """authenticate_sector must send SELECT_CARD (0x43) before SAVE_KEY.

    This is the regression test for the write-then-reauth bug: after any
    write the card returns to IDLE and needs an explicit select before auth.
    """
    resp_req  = build_response(0, ResponseMessage.ACK, b'')
    resp_anti = build_response(0, ResponseMessage.ACK, b'\xEE\xCC\xBB\xAA')
    resp_sel  = build_response(0, ResponseMessage.ACK, b'')
    resp_save = build_response(0, ResponseMessage.ACK, b'')
    resp_auth = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_req + resp_anti + resp_sel + resp_save + resp_auth)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.authenticate_sector(1, b'\xFF' * 6, key_type='A')
    # SELECT_CARD opcode 0x43 must appear in what was written to the serial port
    assert bytes([QueryMessage.SELECT_CARD]) in dummy.written


def test_write_then_reauthenticate(monkeypatch):
    """Simulate write_block followed by authenticate_sector — the exact
    scenario that was failing in the field (examples 05 and 07)."""
    # Write-block response
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    # Re-select + re-auth responses
    resp_req   = build_response(0, ResponseMessage.ACK, b'')
    resp_anti  = build_response(0, ResponseMessage.ACK, b'\x01\x02\x03\x04')
    resp_sel   = build_response(0, ResponseMessage.ACK, b'')
    resp_save  = build_response(0, ResponseMessage.ACK, b'')
    resp_auth  = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_write + resp_req + resp_anti + resp_sel + resp_save + resp_auth)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.write_block(0, b'\xAB' * 16)   # write, card goes IDLE
    r.authenticate_sector(1, b'\xFF' * 6)  # must succeed via auto-reselect
    assert bytes([QueryMessage.SELECT_CARD]) in dummy.written


# --- Value block operation tests (read-modify-write implementation) ---

def test_increment_value(monkeypatch):
    """increment_value reads current, adds delta, writes back."""
    val_bytes = struct.pack('<i', 500)
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_read + resp_write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.increment_value(0, 250)  # 500 + 250 = 750
    # write_value internally uses create_value_block (CREATE_VALUE_BLOCK command)
    assert bytes([QueryMessage.CREATE_VALUE_BLOCK]) in dummy.written
    # The raw payload must contain the LE-encoded result 750
    assert struct.pack('<i', 750) in dummy.written


def test_decrement_value(monkeypatch):
    """decrement_value reads current, subtracts delta, writes back."""
    val_bytes = struct.pack('<i', 1000)
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_read + resp_write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.decrement_value(0, 100)  # 1000 - 100 = 900
    assert bytes([QueryMessage.CREATE_VALUE_BLOCK]) in dummy.written
    assert struct.pack('<i', 900) in dummy.written


def test_increment_value_overflow(monkeypatch):
    """increment_value raises ValueError when result overflows int32."""
    val_bytes = struct.pack('<i', 2**31 - 1)   # max int32
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    dummy = DummySerial(resp_read)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError, match='overflow'):
        r.increment_value(0, 1)


def test_decrement_value_underflow(monkeypatch):
    """decrement_value raises ValueError when result underflows int32."""
    val_bytes = struct.pack('<i', -2**31)   # min int32
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    dummy = DummySerial(resp_read)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError, match='underflow'):
        r.decrement_value(0, 1)


def test_transfer_value(monkeypatch):
    """transfer reads source block and writes to dest block."""
    val_bytes  = struct.pack('<i', 42)
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_read + resp_write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.transfer(source_block=0, dest_block=1)
    assert bytes([QueryMessage.READ_VALUE]) in dummy.written
    assert bytes([QueryMessage.CREATE_VALUE_BLOCK]) in dummy.written


def test_restore_value(monkeypatch):
    """restore re-reads then re-writes the same block."""
    val_bytes  = struct.pack('<i', 99)
    resp_read  = build_response(0, ResponseMessage.ACK, val_bytes)
    resp_write = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_read + resp_write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.restore(0)
    assert bytes([QueryMessage.READ_VALUE]) in dummy.written
    assert bytes([QueryMessage.CREATE_VALUE_BLOCK]) in dummy.written


# =============================================================================
# Phase 7 — DX improvements
# =============================================================================

# --- InvalidMessage.raw_bytes ---

def test_invalid_message_raw_bytes_incomplete_header():
    ser = DummySerial(b'\x01\x02')          # only 2 bytes
    with pytest.raises(InvalidMessage) as exc_info:
        Message.readfrom(ser)
    assert exc_info.value.raw_bytes == b'\x01\x02'


def test_invalid_message_raw_bytes_bad_soh():
    """SOH byte mismatch should carry the offending header in raw_bytes."""
    body = struct.pack('BBBB', 0xFF, 0, 1, 0)   # wrong SOH (0xFF instead of 0x01)
    ser = DummySerial(body)
    with pytest.raises(InvalidMessage) as exc_info:
        Message.readfrom(ser)
    assert len(exc_info.value.raw_bytes) >= 4


# --- GNetPlusError.nak_code ---

def test_gnetplus_error_nak_code():
    err = ResponseMessage(0, ResponseMessage.NAK, b'\x05')
    exc = err.to_error()
    assert exc.nak_code == 0x05


def test_gnetplus_error_nak_code_multi_byte():
    # Non-single-byte raw payload → nak_code should be 0
    err = ResponseMessage(0, ResponseMessage.NAK, b'xy')
    exc = err.to_error()
    assert exc.nak_code == 0


# --- SectorAuth validation ---

def test_sector_auth_valid():
    sa = SectorAuth(key=b'\xFF' * 6, key_type='B', timeout=2.0, flush=False)
    assert sa.key_type == 'B'
    assert sa.timeout == 2.0
    assert sa.flush is False


def test_sector_auth_bad_key_type():
    with pytest.raises(ValueError, match="key_type"):
        SectorAuth(key=b'\xFF' * 6, key_type='C')


def test_sector_auth_bad_key_length():
    with pytest.raises(ValueError, match='6 bytes'):
        SectorAuth(key=b'\xFF' * 5)


# --- CardInfo dataclass ---

def test_card_info_str_and_repr():
    ci = CardInfo(uid='0xAABBCCDD', uid_int=0xAABBCCDD, uid_bytes=b'\xDD\xCC\xBB\xAA')
    assert str(ci) == '0xAABBCCDD'
    assert repr(ci) == "CardInfo(uid='0xAABBCCDD')"


# --- MifareReader.__repr__ ---

def test_mifarereader_repr(monkeypatch):
    class TrackingSerial(DummySerial):
        def isOpen(self):
            return True
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: TrackingSerial(b''))
    r = MifareReader('/dev/ttyUSB0', baudrate=19200, deviceaddr=0)
    text = repr(r)
    assert 'MifareReader' in text
    assert '/dev/ttyUSB0' in text
    assert 'open' in text


# --- get_uid / get_uid_int ---

def _select_responses(uid_bytes: bytes):
    """Helper: build REQUEST + ANTI_COLLISION response pair."""
    resp_req  = build_response(0, ResponseMessage.ACK, b'')
    resp_anti = build_response(0, ResponseMessage.ACK, uid_bytes)
    return resp_req + resp_anti


def test_get_uid(monkeypatch):
    uid_bytes = struct.pack('<L', 0x11223344)
    dummy = DummySerial(_select_responses(uid_bytes))
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.get_uid() == '0x11223344'


def test_get_uid_int(monkeypatch):
    uid_bytes = struct.pack('<L', 0xAABBCCDD)
    dummy = DummySerial(_select_responses(uid_bytes))
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.get_uid_int() == 0xAABBCCDD


# --- scan_tag ---

def test_scan_tag(monkeypatch):
    uid_bytes = struct.pack('<L', 0xDEADBEEF)
    resp_req   = build_response(0, ResponseMessage.ACK, b'')
    resp_anti  = build_response(0, ResponseMessage.ACK, uid_bytes)
    resp_sel   = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_req + resp_anti + resp_sel)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    card = r.scan_tag()
    assert isinstance(card, CardInfo)
    assert card.uid == '0xDEADBEEF'
    assert card.uid_int == 0xDEADBEEF
    assert card.uid_bytes == uid_bytes
    # SELECT_CARD must have been sent
    assert bytes([QueryMessage.SELECT_CARD]) in dummy.written


# --- ping ---

def test_ping_true(monkeypatch):
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.ping() is True
    assert bytes([QueryMessage.POLLING]) in dummy.written


def test_ping_false(monkeypatch):
    resp_nak = build_response(0, ResponseMessage.NAK, b'\x01')
    dummy = DummySerial(resp_nak)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.ping() is False


# --- is_card_present ---

def test_is_card_present_true(monkeypatch):
    resp_req = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_req)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.is_card_present() is True


def test_is_card_present_false(monkeypatch):
    resp_nak = build_response(0, ResponseMessage.NAK, b'\x01')
    dummy = DummySerial(resp_nak)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    assert r.is_card_present() is False


# --- authenticate_sector_cached ---

def test_authenticate_sector_cached(monkeypatch):
    """authenticate_sector_cached must call SELECT_CARD then AUTHENTICATE_KEY (0x2E)
    and must NOT call SAVE_KEY (0x2B)."""
    resp_req  = build_response(0, ResponseMessage.ACK, b'')
    resp_anti = build_response(0, ResponseMessage.ACK, b'\x01\x02\x03\x04')
    resp_sel  = build_response(0, ResponseMessage.ACK, b'')
    resp_auth = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_req + resp_anti + resp_sel + resp_auth)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.authenticate_sector_cached(sector=1, key_type='A')
    assert bytes([QueryMessage.AUTHENTICATE_KEY]) in dummy.written
    assert bytes([QueryMessage.SAVE_KEY]) not in dummy.written


def test_authenticate_sector_cached_bad_key_type(monkeypatch):
    dummy = DummySerial(b'')
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError, match="key_type"):
        r.authenticate_sector_cached(sector=0, key_type='X')


# --- write_sector_uniform ---

def test_write_sector_uniform(monkeypatch):
    resp_ack = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(resp_ack * 3)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    r.write_sector_uniform(b'\xAB' * 16)
    assert dummy.written.count(bytes([QueryMessage.WRITE_BLOCK])) == 3


def test_write_sector_uniform_bad_length(monkeypatch):
    dummy = DummySerial(b'')
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    with pytest.raises(ValueError, match='16 bytes'):
        r.write_sector_uniform(b'\x00' * 8)


# --- read_sector combine fix (b''.join instead of b'''.'''.join) ---

def test_read_sector_combine_bytes(monkeypatch):
    """read_sector(combine=True, raw=True) must return exactly 48 bytes."""
    blocks = [build_response(0, ResponseMessage.ACK, bytes([i]) * 16) for i in range(3)]
    dummy = DummySerial(b''.join(blocks))
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    result = r.read_sector(raw=True, combine=True)
    assert isinstance(result, bytes)
    assert len(result) == 48
    # Content must be three consecutive blocks without any separator
    assert result == bytes([0]) * 16 + bytes([1]) * 16 + bytes([2]) * 16


# --- auth= parameter on read_blocks / write_blocks ---

def _make_sector_responses(uid_bytes=b'\x01\x02\x03\x04', num_data_blocks=1):
    """Return the response bytes for full auth + N data reads."""
    req   = build_response(0, ResponseMessage.ACK, b'')
    anti  = build_response(0, ResponseMessage.ACK, uid_bytes)
    sel   = build_response(0, ResponseMessage.ACK, b'')
    save  = build_response(0, ResponseMessage.ACK, b'')
    auth  = build_response(0, ResponseMessage.ACK, b'')
    reads = b''.join(
        build_response(0, ResponseMessage.ACK, b'\xCC' * 16)
        for _ in range(num_data_blocks)
    )
    return req + anti + sel + save + auth + reads


def test_read_blocks_auth_param(monkeypatch):
    """read_blocks with auth= SectorAuth should authenticate and return data."""
    dummy = DummySerial(_make_sector_responses(num_data_blocks=2))
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    sa = SectorAuth(key=b'\xFF' * 6)
    result = r.read_blocks({1: [0, 1]}, auth={1: sa})
    assert 1 in result
    assert set(result[1].keys()) == {0, 1}


def test_write_blocks_auth_param(monkeypatch):
    """write_blocks with auth= SectorAuth should authenticate then write."""
    req   = build_response(0, ResponseMessage.ACK, b'')
    anti  = build_response(0, ResponseMessage.ACK, b'\x01\x02\x03\x04')
    sel   = build_response(0, ResponseMessage.ACK, b'')
    save  = build_response(0, ResponseMessage.ACK, b'')
    auth  = build_response(0, ResponseMessage.ACK, b'')
    write = build_response(0, ResponseMessage.ACK, b'')
    dummy = DummySerial(req + anti + sel + save + auth + write)
    monkeypatch.setattr(serial, 'Serial', lambda *args, **kwargs: dummy)
    r = MifareReader()
    sa = SectorAuth(key=b'\xFF' * 6)
    r.write_blocks({1: {0: b'\xAB' * 16}}, auth={1: sa})
    assert bytes([QueryMessage.SAVE_KEY]) in dummy.written
    assert bytes([QueryMessage.WRITE_BLOCK]) in dummy.written
