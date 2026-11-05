"""End-to-end tests of MifareReader against the simulated reader and card."""

import asyncio
import threading
import time

import pytest

from mifarepy import (
    AuthenticationError,
    GNetPlusError,
    MifareReader,
    NoCardError,
    NotAuthenticatedError,
    SectorAuth,
)
from mifarepy.protocol import QueryMessage
from mifarepy.simulator import SimulatedCard, SimulatedReader

KEY = bytes.fromhex('FFFFFFFFFFFF')
OTHER_KEY = bytes.fromhex('A0A1A2A3A4A5')


# --- detection ---------------------------------------------------------------

def test_uid_matches_card(mifare_reader, mifare_card):
    assert mifare_reader.get_uid() == mifare_card.uid_str
    assert mifare_reader.scan_tag().uid == mifare_card.uid_str
    assert mifare_reader.get_uid_int() == int(mifare_card.uid_str, 16)


def test_uid_string_roundtrip():
    card = SimulatedCard(uid='0xD39BC634')
    assert MifareReader.simulated(card).get_uid() == '0xD39BC634'


def test_presence_and_ping(mifare_reader, mifare_simulator):
    assert mifare_reader.ping()
    assert mifare_reader.is_card_present()
    mifare_simulator.remove_card()
    assert not mifare_reader.is_card_present()
    with pytest.raises(NoCardError, match='No tag in field'):
        mifare_reader.get_uid()


def test_version(mifare_reader):
    assert mifare_reader.get_version() == 'SIM0001 V1.0 (mifarepy simulator)'


def test_halt_and_request_all(mifare_reader, mifare_card):
    mifare_reader.scan_tag()
    mifare_reader.halt()
    assert not mifare_reader.is_card_present()          # REQUEST ignores halted cards
    assert mifare_reader.request_all() == mifare_card.uid_str


def test_rf_power_cycle_wakes_halted_card(mifare_reader):
    mifare_reader.halt()
    mifare_reader.rf_power(False)
    assert not mifare_reader.is_card_present()
    mifare_reader.rf_power(True)
    assert mifare_reader.is_card_present()


def test_empty_reader():
    reader = MifareReader.simulated(empty=True)
    assert not reader.is_card_present()


# --- authentication and blocks ----------------------------------------------

def test_read_write_block(mifare_reader, mifare_card):
    mifare_reader.authenticate_sector(1, KEY)
    mifare_reader.write_block(2, b'Hello, mifarepy!')
    assert mifare_reader.read_block(2, raw=True) == b'Hello, mifarepy!'
    assert mifare_card.read(1, 2) == b'Hello, mifarepy!'


def test_wrong_key_raises_authentication_error_with_context(mifare_reader):
    with pytest.raises(AuthenticationError) as info:
        mifare_reader.authenticate_sector(3, OTHER_KEY, 'B')
    err = info.value
    assert isinstance(err, GNetPlusError)
    assert err.nak_code == 0x04
    assert 'sector 3, key B' in str(err)
    assert 'Hint:' in str(err) and err.hint


def test_custom_keys(mifare_card):
    mifare_card.set_trailer(2, key_a=OTHER_KEY, key_b=KEY)
    reader = MifareReader.simulated(mifare_card)
    with pytest.raises(AuthenticationError):
        reader.authenticate_sector(2, KEY, 'A')
    reader.authenticate_sector(2, OTHER_KEY, 'A')
    reader.authenticate_sector(2, KEY, 'B')


def test_read_without_auth_raises_not_authenticated(mifare_reader):
    mifare_reader.scan_tag()
    with pytest.raises(NotAuthenticatedError, match='block 0'):
        mifare_reader.read_block(0)


def test_trailer_hides_key_a(mifare_reader):
    mifare_reader.authenticate_sector(0, KEY)
    trailer = mifare_reader.read_block(3, raw=True)
    assert trailer[:6] == b'\x00' * 6
    assert trailer[6:10] == bytes.fromhex('FF078069')


def test_cached_authentication(mifare_reader):
    mifare_reader.authenticate_sector(1, KEY)
    mifare_reader.authenticate_sector_cached(2)
    mifare_reader.read_block(0)


def test_sector_and_bulk_io(mifare_reader, mifare_card):
    mifare_reader.authenticate_sector(4, KEY)
    mifare_reader.write_sector(bytes(range(48)))
    assert mifare_reader.read_sector(raw=True, combine=True) == bytes(range(48))
    mifare_reader.write_blocks({5: {0: b'\xaa' * 16}, 6: b'\xbb' * 16}, auth={
        5: SectorAuth(key=KEY), 6: SectorAuth(key=KEY)})
    result = mifare_reader.read_blocks({5: [0], 6: [0, 1, 2]}, raw=True, keys=KEY)
    assert result[5][0] == b'\xaa' * 16
    assert all(v == b'\xbb' * 16 for v in result[6].values())
    assert mifare_card.read(6, 3)[6:10] == bytes.fromhex('FF078069')   # trailer untouched


def test_4k_large_sector():
    card = SimulatedCard(size='4K')
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(36, KEY)
    reader.write_sector_uniform(b'\x42' * 16)
    data = reader.read_sector()
    assert len(data) == 15
    assert card.read(36, 14) == b'\x42' * 16
    assert card.read(36, 15)[6:10] == bytes.fromhex('FF078069')


# --- value blocks ------------------------------------------------------------

@pytest.mark.parametrize('value_ops', ['auto', 'native', 'software'])
def test_value_blocks_all_modes(value_ops):
    card = SimulatedCard()
    reader = MifareReader.simulated(card, value_ops=value_ops)
    reader.authenticate_sector(2, KEY)
    reader.create_value_block(0, 1000)
    reader.increment_value(0, 250)
    reader.decrement_value(0, 100)
    assert reader.read_value(0) == 1150
    reader.create_value_block(1, 0)
    reader.transfer(0, 1)
    reader.restore(1)
    assert reader.read_value(1) == 1150
    assert card.value(2, 1) == 1150


def test_native_mode_sends_set_value():
    reader = MifareReader.simulated(value_ops='native')
    reader.authenticate_sector(1, KEY)
    reader.create_value_block(0, 5)
    reader.increment_value(0, 5)
    assert QueryMessage.SET_VALUE in [q.function for q in reader.serial.queries]


def test_reading_non_value_block_fails(mifare_reader):
    mifare_reader.authenticate_sector(1, KEY)
    with pytest.raises(GNetPlusError):
        mifare_reader.read_value(0)


# --- events ------------------------------------------------------------------

def test_wait_for_card_already_present(mifare_reader, mifare_card):
    assert mifare_reader.wait_for_card(timeout=1) == mifare_card.uid_str


def test_wait_for_card_arrives_later():
    sim = SimulatedReader()
    reader = MifareReader.from_serial(sim)
    card = SimulatedCard(uid='0x01020304')
    threading.Timer(0.2, sim.place_card, args=(card,)).start()
    start = time.monotonic()
    assert reader.wait_for_card(timeout=3) == '0x01020304'
    assert time.monotonic() - start < 2


def test_wait_for_card_times_out():
    reader = MifareReader.simulated(empty=True)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        reader.wait_for_card(timeout=0.3)
    assert time.monotonic() - start < 2


def test_wait_for_card_async():
    sim = SimulatedReader()
    reader = MifareReader.from_serial(sim)

    async def main():
        loop = asyncio.get_running_loop()
        loop.call_later(0.2, sim.place_card, SimulatedCard(uid='0xCAFEBABE'))
        return await reader.wait_for_card_async(timeout=3)

    assert asyncio.run(main()) == '0xCAFEBABE'


def test_close_turns_auto_mode_off():
    sim = SimulatedReader(SimulatedCard())
    with MifareReader.from_serial(sim) as reader:
        reader.set_auto_mode(True)
        assert sim.auto_mode
    assert not sim.auto_mode
    assert not sim.is_open


# --- simulator details -------------------------------------------------------

def test_unknown_command_naks(mifare_reader):
    mifare_reader.sendmsg(QueryMessage.THERMOMETER)
    with pytest.raises(GNetPlusError) as info:
        mifare_reader.readmsg()
    assert info.value.nak_code == 0xE6


def test_echo(mifare_reader):
    mifare_reader.sendmsg(QueryMessage.ECHO, b'hello')
    assert mifare_reader.readmsg().data == b'hello'


def test_card_validation():
    with pytest.raises(ValueError):
        SimulatedCard(size='2K')
    with pytest.raises(ValueError):
        SimulatedCard(uid=b'\x01\x02')
    card = SimulatedCard()
    with pytest.raises(ValueError):
        card.write(1, 0, b'short')
    with pytest.raises(ValueError):
        card.set_trailer(1, key_a=b'\x00')


def test_manufacturer_block_is_read_only(mifare_reader):
    mifare_reader.authenticate_sector(0, KEY)
    with pytest.raises(GNetPlusError):
        mifare_reader.write_block(0, b'\x00' * 16)
