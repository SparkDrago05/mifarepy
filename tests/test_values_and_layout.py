"""Tests for native value-block commands (with fallback) and 4K sector layout."""

import struct

import pytest
import serial

from mifarepy import MifareReader, layout
from mifarepy.protocol import GNetPlusError, Message, QueryMessage, ResponseMessage, gencrc
from mifarepy.reader import VALUE_DECREMENT, VALUE_INCREMENT


class ScriptedSerial:
    """Fake serial port that replays queued reader responses and records queries."""

    def __init__(self, responses):
        self._buf = b''.join(responses)
        self.written = []
        self.timeout = None
        self.is_open = True

    def write(self, data):
        self.written.append(bytes(data))

    def read(self, n):
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def reset_input_buffer(self):
        pass

    def close(self):
        self.is_open = False

    def functions(self):
        """Function codes of every query sent, in order."""
        return [frame[2] for frame in self.written]

    def payloads(self, function):
        return [frame[4:4 + frame[3]] for frame in self.written if frame[2] == function]


def resp(func=ResponseMessage.ACK, data=b''):
    body = struct.pack('BBB', 0, func, len(data)) + data
    return bytes([Message.SOH]) + body + struct.pack('>H', gencrc(body))


def ack():
    return resp()


def nak(code):
    return resp(ResponseMessage.NAK, bytes([code]))


def value(v):
    return resp(data=struct.pack('<i', v))


def make_reader(monkeypatch, responses, **kwargs):
    fake = ScriptedSerial(responses)
    monkeypatch.setattr(serial, 'Serial', lambda *a, **k: fake)
    return MifareReader(**kwargs), fake


Q = QueryMessage


# --- native value commands ---------------------------------------------------

@pytest.mark.parametrize('mode', ['auto', 'software'])
def test_increment_and_decrement_use_read_modify_write(monkeypatch, mode):
    # SET_VALUE is never sent outside 'native' mode (PGM0487 V1.4R0 firmware
    # computes it wrongly), so no incorrect value is ever written to the card.
    r, fake = make_reader(monkeypatch, [value(1000), ack(), value(1250), ack()], value_ops=mode)
    r.increment_value(0, 250)
    r.decrement_value(0, 250)
    assert Q.SET_VALUE not in fake.functions()
    assert fake.functions() == [Q.READ_VALUE, Q.CREATE_VALUE_BLOCK] * 2
    assert fake.payloads(Q.CREATE_VALUE_BLOCK) == [
        b'\x00' + struct.pack('<i', 1250),
        b'\x00' + struct.pack('<i', 1000),
    ]


def test_native_increment_uses_set_value_and_verifies(monkeypatch):
    r, fake = make_reader(monkeypatch, [value(100), ack(), value(125)], value_ops='native')
    r.increment_value(1, 25)
    assert fake.functions() == [Q.READ_VALUE, Q.SET_VALUE, Q.READ_VALUE]
    assert fake.payloads(Q.SET_VALUE) == [bytes([1, VALUE_INCREMENT]) + struct.pack('<i', 25)]
    assert Q.CREATE_VALUE_BLOCK not in fake.functions()
    assert r._native_values_ok is True


def test_native_decrement_uses_set_value(monkeypatch):
    r, fake = make_reader(monkeypatch, [value(100), ack(), value(60)], value_ops='native')
    r.decrement_value(2, 40)
    assert fake.payloads(Q.SET_VALUE) == [bytes([2, VALUE_DECREMENT]) + struct.pack('<i', 40)]


def test_transfer_uses_restore_then_transfer(monkeypatch):
    r, fake = make_reader(monkeypatch, [value(7), ack(), ack(), value(7)])
    r.transfer(0, 1)
    assert fake.functions() == [Q.READ_VALUE, Q.RESTORE, Q.TRANSFER, Q.READ_VALUE]
    assert fake.payloads(Q.RESTORE) == [b'\x00']
    assert fake.payloads(Q.TRANSFER) == [b'\x01']
    assert fake.payloads(Q.READ_VALUE)[-1] == b'\x01'  # verified the destination


def test_restore_uses_restore_then_transfer_on_same_block(monkeypatch):
    r, fake = make_reader(monkeypatch, [value(9), ack(), ack(), value(9)])
    r.restore(2)
    assert fake.payloads(Q.RESTORE) == [b'\x02']
    assert fake.payloads(Q.TRANSFER) == [b'\x02']


def test_unsupported_command_falls_back_and_is_remembered(monkeypatch):
    # authenticate_sector: REQUEST, ANTI_COLLISION, SELECT, SAVE_KEY, AUTHENTICATE
    auth = [resp(data=b'\x04\x00'), resp(data=b'\x01\x02\x03\x04'), ack(), ack(), ack()]
    # authenticate_sector_cached: REQUEST, ANTI_COLLISION, SELECT, AUTHENTICATE_KEY
    cached = [resp(data=b'\x04\x00'), resp(data=b'\x01\x02\x03\x04'), ack(), ack()]
    responses = (
        auth
        + [value(10), nak(0xE6)]   # read, native RESTORE rejected as unknown command
        + cached                   # re-authenticate with the stored key
        + [ack()]                  # CREATE_VALUE_BLOCK fallback write
        + [value(15), ack()]       # second transfer goes straight to read-modify-write
    )
    r, fake = make_reader(monkeypatch, responses)
    r.authenticate_sector(1, b'\xff' * 6)
    r.transfer(0, 1)
    assert r._native_values_ok is False
    assert fake.payloads(Q.CREATE_VALUE_BLOCK)[-1] == b'\x01' + struct.pack('<i', 10)
    assert Q.AUTHENTICATE_KEY in fake.functions()

    before = len(fake.written)
    r.transfer(0, 1)
    assert fake.functions()[before:] == [Q.READ_VALUE, Q.CREATE_VALUE_BLOCK]
    assert fake.payloads(Q.CREATE_VALUE_BLOCK)[-1] == b'\x01' + struct.pack('<i', 15)


def test_wrong_native_result_is_corrected(monkeypatch):
    # Reader accepts RESTORE/TRANSFER but the destination ends up wrong.
    r, fake = make_reader(monkeypatch, [value(100), ack(), ack(), value(999), ack()])
    r.transfer(0, 1)
    assert fake.payloads(Q.CREATE_VALUE_BLOCK) == [b'\x01' + struct.pack('<i', 100)]
    assert r._native_values_ok is False


def test_native_mode_raises_instead_of_falling_back(monkeypatch):
    r, _ = make_reader(monkeypatch, [value(100), nak(0xE6)], value_ops='native')
    with pytest.raises(GNetPlusError):
        r.increment_value(0, 1)


def test_native_mode_raises_on_wrong_result(monkeypatch):
    r, _ = make_reader(monkeypatch, [value(100), ack(), value(5)], value_ops='native')
    with pytest.raises(GNetPlusError, match='expected 101'):
        r.increment_value(0, 1)


def test_fallback_without_known_sector_explains(monkeypatch):
    r, _ = make_reader(monkeypatch, [value(100), nak(0x10)])
    with pytest.raises(RuntimeError, match='authenticate_sector'):
        r.restore(0)


def test_invalid_value_ops(monkeypatch):
    with pytest.raises(ValueError, match='value_ops'):
        make_reader(monkeypatch, [], value_ops='magic')


# --- layout helpers ----------------------------------------------------------

@pytest.mark.parametrize('sector,count,trailer', [(0, 4, 3), (31, 4, 3), (32, 16, 15), (39, 16, 15)])
def test_layout_block_counts(sector, count, trailer):
    assert layout.blocks_in_sector(sector) == count
    assert layout.trailer_block(sector) == trailer
    assert list(layout.data_blocks(sector)) == list(range(trailer))


def test_layout_absolute_roundtrip():
    for absolute in range(256):
        sector, block = layout.sector_of(absolute)
        assert layout.absolute_block(sector, block) == absolute
    assert layout.absolute_block(32, 0) == 128
    assert layout.absolute_block(39, 15) == 255


@pytest.mark.parametrize('bad', [-1, 40])
def test_layout_rejects_bad_sector(bad):
    with pytest.raises(ValueError):
        layout.blocks_in_sector(bad)


def test_layout_rejects_bad_block():
    with pytest.raises(ValueError):
        layout.absolute_block(1, 4)
    with pytest.raises(ValueError):
        layout.sector_of(256)


# --- 4K large sectors --------------------------------------------------------

def test_read_sector_large_sector_reads_15_blocks(monkeypatch):
    r, fake = make_reader(monkeypatch, [resp(data=bytes([i]) * 16) for i in range(15)])
    data = r.read_sector(35, raw=True)
    assert sorted(data) == list(range(15))
    assert fake.payloads(Q.READ_BLOCK) == [bytes([i]) for i in range(15)]


def test_read_sector_uses_last_authenticated_sector(monkeypatch):
    auth = [resp(data=b'\x02\x00'), resp(data=b'\x01\x02\x03\x04'), ack(), ack(), ack()]
    r, fake = make_reader(monkeypatch, auth + [resp(data=b'\x00' * 16)] * 15)
    r.authenticate_sector(33, b'\xff' * 6)
    r.read_sector()
    assert len(fake.payloads(Q.READ_BLOCK)) == 15


def test_read_sector_small_sector_unchanged(monkeypatch):
    r, fake = make_reader(monkeypatch, [resp(data=b'\x00' * 16)] * 3)
    r.read_sector()
    assert fake.payloads(Q.READ_BLOCK) == [b'\x00', b'\x01', b'\x02']


def test_write_sector_large_sector_rejects_trailer(monkeypatch):
    r, _ = make_reader(monkeypatch, [])
    with pytest.raises(ValueError, match='sector trailer'):
        r.write_sector({15: b'\x00' * 16}, sector=34)


def test_write_sector_large_sector_chunks(monkeypatch):
    r, fake = make_reader(monkeypatch, [ack()] * 5)
    r.write_sector(bytes(16 * 5), sector=34)
    assert [p[0] for p in fake.payloads(Q.WRITE_BLOCK)] == [0, 1, 2, 3, 4]


def test_write_sector_uniform_large_sector(monkeypatch):
    r, fake = make_reader(monkeypatch, [ack()] * 15)
    r.write_sector_uniform(b'\xaa' * 16, sector=39)
    assert len(fake.payloads(Q.WRITE_BLOCK)) == 15


def test_write_sector_too_much_data(monkeypatch):
    r, _ = make_reader(monkeypatch, [])
    with pytest.raises(ValueError, match='multiple of 16'):
        r.write_sector(bytes(16 * 4))
