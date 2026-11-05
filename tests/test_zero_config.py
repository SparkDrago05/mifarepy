"""Tests for port discovery, MifareReader.auto(), connection hints, errors and tracing."""

import errno
import io
import logging
from types import SimpleNamespace

import pytest
import serial

from mifarepy import (
    AuthenticationError,
    CardReadError,
    GNetPlusError,
    InvalidMessage,
    MifareReader,
    NoCardError,
    ReaderConnectionError,
    ReaderNotFoundError,
    ReaderProtocolError,
    ValueBlockError,
    disable_wire_trace,
    discovery,
    enable_wire_trace,
)
from mifarepy.protocol import NAK_ERROR_CLASSES, QueryMessage, ResponseMessage, error_for_nak
from mifarepy.simulator import SimulatedCard, SimulatedReader
from mifarepy.trace import format_frame


def fake_port(device, vid=None, pid=None, description='USB-Serial'):
    return SimpleNamespace(device=device, vid=vid, pid=pid, description=description)


# --- discovery ---------------------------------------------------------------

def test_find_ports_prefers_pl2303(monkeypatch):
    monkeypatch.setattr(discovery.list_ports, 'comports', lambda: [
        fake_port('/dev/ttyS0', description='n/a'),
        fake_port('/dev/ttyUSB1', 0x0403, 0x6001, 'FTDI'),
        fake_port('/dev/ttyUSB0', 0x067B, 0x2303, 'PL2303'),
    ])
    assert [p.device for p in discovery.find_ports()] == ['/dev/ttyUSB0']
    everything = discovery.find_ports(include_all=True)
    assert everything[0].device == '/dev/ttyUSB0' and everything[0].likely_reader
    assert {p.device for p in everything} == {'/dev/ttyS0', '/dev/ttyUSB0', '/dev/ttyUSB1'}


def _patch_serial(monkeypatch, devices):
    """Make serial.Serial(port) return a simulator for ports in *devices*."""
    def factory(port, **kwargs):
        if port not in devices:
            raise serial.SerialException(errno.ENOENT, f'could not open port {port}')
        sim = devices[port]
        sim.port = port
        return sim
    monkeypatch.setattr(serial, 'Serial', factory)


def test_auto_opens_first_answering_reader(monkeypatch):
    monkeypatch.setattr(discovery.list_ports, 'comports', lambda: [
        fake_port('/dev/ttyUSB0', 0x067B, 0x2303),
        fake_port('/dev/ttyUSB1', 0x067B, 0x23A3),
    ])
    silent = SimulatedReader(SimulatedCard())
    silent.write = lambda data: len(data)          # a PL2303 that isn't a reader
    good = SimulatedReader(SimulatedCard(uid='0x0A0B0C0D'))
    _patch_serial(monkeypatch, {'/dev/ttyUSB0': silent, '/dev/ttyUSB1': good})

    reader = MifareReader.auto()
    assert reader.port == '/dev/ttyUSB1'
    assert reader.get_uid() == '0x0A0B0C0D'
    assert not silent.is_open


def test_auto_without_probe(monkeypatch):
    monkeypatch.setattr(discovery.list_ports, 'comports', lambda: [fake_port('/dev/ttyUSB0', 0x067B, 0x2303)])
    sim = SimulatedReader()
    _patch_serial(monkeypatch, {'/dev/ttyUSB0': sim})
    MifareReader.auto(probe=False)
    assert sim.queries == []          # nothing was sent


def test_auto_not_found_lists_ports(monkeypatch):
    monkeypatch.setattr(discovery.list_ports, 'comports', lambda: [fake_port('/dev/ttyS0', description='n/a')])
    with pytest.raises(ReaderNotFoundError) as info:
        MifareReader.auto()
    assert '/dev/ttyS0' in str(info.value)
    assert 'include_all=True' in str(info.value)
    assert info.value.ports == [('/dev/ttyS0', 'n/a')]
    assert isinstance(info.value, RuntimeError)


def test_auto_no_ports_at_all(monkeypatch):
    monkeypatch.setattr(discovery.list_ports, 'comports', lambda: [])
    with pytest.raises(ReaderNotFoundError, match='No serial ports'):
        MifareReader.auto()


# --- connection errors -------------------------------------------------------

@pytest.mark.parametrize('exc, expected', [
    (serial.SerialException(errno.EACCES, 'Permission denied'), 'ermission'),
    (serial.SerialException(errno.ENOENT, 'No such file or directory'), 'MifareReader.auto()'),
    (serial.SerialException(errno.EBUSY, 'Device or resource busy'), 'in use'),
    (serial.SerialException('something odd'), 'Check the cable'),
])
def test_connection_error_hints(monkeypatch, exc, expected):
    def boom(*args, **kwargs):
        raise exc
    monkeypatch.setattr(serial, 'Serial', boom)
    with pytest.raises(ReaderConnectionError) as info:
        MifareReader('/dev/ttyUSB9')
    assert isinstance(info.value, RuntimeError)      # backwards compatible
    assert 'Unable to open port /dev/ttyUSB9' in str(info.value)
    assert expected in info.value.hint
    assert info.value.port == '/dev/ttyUSB9'


# --- error classes -----------------------------------------------------------

@pytest.mark.parametrize('code, cls', [
    (0x1F, NoCardError), (0x03, NoCardError), (0x04, AuthenticationError),
    (0x12, CardReadError), (0x10, ValueBlockError), (0xE6, ReaderProtocolError),
])
def test_nak_maps_to_subclass(code, cls):
    err = ResponseMessage(0, ResponseMessage.NAK, bytes([code])).to_error()
    assert type(err) is cls
    assert isinstance(err, GNetPlusError)
    assert err.nak_code == code
    assert err.hint and 'Hint:' in str(err)


def test_unknown_nak_is_plain_gnetplus_error():
    err = error_for_nak(b'\x99')
    assert type(err) is GNetPlusError
    assert err.code_description == 'Unknown error'
    assert 'Hint' not in str(err)


def test_every_mapped_code_has_a_hint():
    for code, cls in NAK_ERROR_CLASSES.items():
        assert cls.default_hint, hex(code)


def test_context_in_message():
    err = error_for_nak(b'\x04', 'sector 3, key A')
    assert 'sector 3, key A' in str(err)


def test_explicit_hint_overrides_default():
    assert GNetPlusError('x', b'\x04', hint='custom').hint == 'custom'
    assert str(AuthenticationError('x', b'\x04', hint='')) == 'x'


# --- tracing -----------------------------------------------------------------

def test_trace_logs_frames_and_hides_keys():
    stream = io.StringIO()
    handler = enable_wire_trace(stream)
    try:
        reader = MifareReader.simulated()
        with pytest.raises(AuthenticationError):
            reader.authenticate_sector(1, bytes.fromhex('A1B2C3D4E5F6'), 'A')
    finally:
        disable_wire_trace(handler)
    out = stream.getvalue()
    assert 'TX SAVE_KEY' in out and 'TX AUTHENTICATE' in out
    assert 'RX NAK 0x04' in out and 'Authentication error' in out   # default keys don't match
    assert 'A1 B2' not in out and '** ** ** ** ** **' in out
    assert logging.getLogger('mifarepy.wire').level == logging.NOTSET


def test_trace_can_show_keys():
    stream = io.StringIO()
    handler = enable_wire_trace(stream, show_keys=True)
    try:
        MifareReader.simulated().authenticate_sector(1, bytes.fromhex('FFFFFFFFFFFF'))
    finally:
        disable_wire_trace(handler)
    assert 'FF FF FF FF FF FF' in stream.getvalue()


def test_format_frame_variants():
    assert 'TX ECHO' in format_frame('TX', bytes(QueryMessage(0, QueryMessage.ECHO, b'hi')))
    assert 'TX 0x77' in format_frame('TX', bytes(QueryMessage(0, 0x77, b'')))
    assert "RX EVN" in format_frame('RX', bytes(ResponseMessage(0, ResponseMessage.EVN, b'I')))
    assert 'short frame' in format_frame('RX', b'\x01\x00')


def test_trace_logs_partial_frames():
    stream = io.StringIO()
    handler = enable_wire_trace(stream)
    sim = SimulatedReader(SimulatedCard())
    sim.write = lambda data: len(data)
    sim._buffer = b'\x01\x00'
    sim.timeout = 0
    reader = MifareReader.from_serial(sim)
    try:
        with pytest.raises(InvalidMessage):
            reader.readmsg()
    finally:
        disable_wire_trace(handler)
    assert 'short frame' in stream.getvalue()


def test_from_serial_repr():
    sim = SimulatedReader()
    reader = MifareReader.from_serial(sim)
    assert "port='simulated'" in repr(reader)
