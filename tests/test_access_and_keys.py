"""Tests for access bits (mifarepy.access), key rings (mifarepy.keys), trailer
writes, card-type detection and the simulator's access-condition enforcement."""

import json
import struct

import pytest

from mifarepy import CardReadError, CardWriteError, MifareReader, NotAuthenticatedError, QueryMessage, cli, layout
from mifarepy.access import (
    DATA_PRESETS,
    TRAILER_PRESETS,
    TRANSPORT_ACCESS,
    AccessBits,
    UnsafeTrailerError,
    build_trailer,
    check_trailer,
    decode_trailer,
)
from mifarepy.dump import read_card, write_card
from mifarepy.keys import DEFAULT_KEY, KeyRing, diversify_key, parse_key
from mifarepy.protocol import GNetPlusError, ValueBlockError
from mifarepy.simulator import SimulatedCard, SimulatedReader

KEY_A = bytes.fromhex('A0A1A2A3A4A5')
KEY_B = bytes.fromhex('B0B1B2B3B4B5')
MASTER = bytes(range(16))


# --- access bits ------------------------------------------------------------------

@pytest.mark.parametrize('hexbits, data, trailer', [
    ('FF078069', ('000', '000', '000'), '001'),     # new card
    ('7F078869', ('000', '000', '000'), '011'),
    ('78778869', ('100', '100', '100'), '011'),
    ('08778F69', ('110', '110', '110'), '011'),
])
def test_decode_known_access_bytes(hexbits, data, trailer):
    bits = AccessBits.from_bytes(bytes.fromhex(hexbits))
    assert bits.data == data and bits.trailer == trailer
    assert str(bits) == hexbits
    assert decode_trailer(KEY_A + bytes.fromhex(hexbits) + KEY_B) == bits


def test_every_condition_round_trips():
    for d0 in range(8):
        for t in range(8):
            bits = AccessBits.build([d0, (d0 + 1) % 8, (d0 + 5) % 8], t, gpb=0x42)
            assert AccessBits.from_bytes(bits.to_bytes()) == bits


def test_build_accepts_presets_bits_and_ints():
    assert AccessBits.build().to_bytes() == TRANSPORT_ACCESS
    assert AccessBits.build('value', 'key-b').data == ('110',) * 3
    assert AccessBits.build(['open', '010', 7], 3).data == ('000', '010', '111')
    assert AccessBits.build(['open', '010', (1, 1, 1)], 3).data[2] == '111'
    assert set(DATA_PRESETS.values()) == {format(i, '03b') for i in range(8)}
    assert 'key-b' in TRAILER_PRESETS


@pytest.mark.parametrize('kwargs, message', [
    ({'data': 'nope'}, 'unknown data condition'),
    ({'trailer': '2'}, 'unknown trailer condition'),
    ({'data': 9}, '0-7'),
    ({'data': ['open', 'open']}, 'list of three'),
    ({'data': [(1, 2, 0), 'open', 'open']}, 'three bits'),
    ({'gpb': 256}, 'gpb'),
])
def test_build_rejects_bad_input(kwargs, message):
    with pytest.raises(ValueError, match=message):
        AccessBits.build(**kwargs)


def test_invalid_access_bytes_are_refused():
    with pytest.raises(UnsafeTrailerError, match='blocks the whole sector'):
        AccessBits.from_bytes(bytes.fromhex('FF078169'))
    with pytest.raises(ValueError, match='4 access bytes'):
        AccessBits.from_bytes(b'\x00\x00')
    assert AccessBits.from_bytes(bytes.fromhex('FF0780')).gpb == 0x69


def test_check_and_build_trailer_guard_permanent_bits():
    trailer = build_trailer(KEY_A, KEY_B, data='write-b', trailer='key-b')
    assert trailer[:6] == KEY_A and trailer[10:] == KEY_B
    assert str(check_trailer(trailer)) == '78778869'
    for name in ('a-keys', 'frozen', 'read-only', 'permanent', '110'):
        with pytest.raises(UnsafeTrailerError, match='allow_permanent'):
            build_trailer(KEY_A, KEY_B, trailer=name)
    assert build_trailer(KEY_A, KEY_B, trailer='permanent', allow_permanent=True)[6:10] != TRANSPORT_ACCESS
    with pytest.raises(ValueError, match='6 bytes'):
        build_trailer(KEY_A[:5], KEY_B)


def test_rights_and_allows():
    transport = AccessBits.build()
    assert transport.key_b_readable and not transport.is_permanent
    assert transport.data_rights(0)['write'] == 'A'              # Key B is data here
    assert transport.allows('write', 'A', 0) and not transport.allows('write', 'B', 0)
    managed = AccessBits.build(['read-only', 'value', 'key-b'], 'key-b')
    assert not managed.key_b_readable
    assert managed.allows('read', 'A', 0) and not managed.allows('write', 'B', 0)
    assert managed.allows('increment', 'B', 1) and not managed.allows('increment', 'A', 1)
    assert not managed.allows('read', 'A', 2) and managed.allows('read', 'B', 2)
    assert managed.allows('write_access', 'B') and not managed.allows('write_access', 'A')
    assert managed.trailer_rights()['read_key_b'] == 'never'


def test_describe_in_plain_language():
    text = AccessBits.build(['read-only', 'value', 'locked'], 'key-b').describe()
    assert 'Block 0 (010, read-only): read: A or B, write: never' in text
    assert 'increment: B, decrement: A or B' in text
    assert 'Block 2 (111, locked): read: never' in text
    assert 'change access bits: B' in text
    assert 'Blocks 5-9' in AccessBits.build().describe(blocks_per_group=5)
    assert 'never be changed' in AccessBits.build(trailer='110').describe()
    assert 'permanent' in AccessBits.build(trailer='110').describe()
    assert 'gives no access' in AccessBits.build().describe()


# --- keys ---------------------------------------------------------------------------

def test_parse_key():
    assert parse_key('a0a1a2a3a4a5') == KEY_A
    assert parse_key('A0:A1:A2:A3:A4:A5') == KEY_A
    assert parse_key('0xA0A1A2A3A4A5') == KEY_A
    assert parse_key(KEY_A) == KEY_A
    for bad in ('A0A1', 'ZZZZZZZZZZZZ', b'\x00'):
        with pytest.raises(ValueError):
            parse_key(bad)


def test_keyring_candidates_known_keys_first():
    ring = KeyRing(sectors={3: {'B': KEY_B}})
    ring.set(3, key_a=KEY_A)
    assert ring.candidates(3) == [('A', KEY_A), ('B', KEY_B), ('A', DEFAULT_KEY), ('B', DEFAULT_KEY)]
    assert ring.candidates(1, 'B') == [('B', DEFAULT_KEY)]
    assert ring.get(3, 'B') == KEY_B and ring.get(4) is None
    ring.add(DEFAULT_KEY)                       # duplicates ignored
    assert len(ring.keys) == 1 and len(ring) == 3
    assert 'KeyRing(1 general key(s), 1 sector(s)' in repr(ring)
    assert KeyRing(keys=[]).candidates(0) == []
    with pytest.raises(ValueError, match='0-39'):
        ring.set(40, key_a=KEY_A)


def test_keyring_files(tmp_path):
    (tmp_path / 'k.dic').write_text('# MCT style\nA0A1A2A3A4A5\n\nffffffffffff  # factory\n')
    ring = KeyRing.load(tmp_path / 'k.dic')
    assert ring.keys == [KEY_A, DEFAULT_KEY]
    (tmp_path / 'bad.keys').write_text('A0A1A2\n')
    with pytest.raises(ValueError, match='line 1'):
        KeyRing.load(tmp_path / 'bad.keys')

    ring = KeyRing(keys=[KEY_A], sectors={2: {'A': KEY_A, 'B': KEY_B}})
    ring.save(tmp_path / 'k.json')
    loaded = KeyRing.load(tmp_path / 'k.json')
    assert loaded.keys == [KEY_A] and loaded.get(2, 'B') == KEY_B
    assert json.loads((tmp_path / 'k.json').read_text())['sectors']['2']['A'] == 'A0A1A2A3A4A5'
    ring.save(tmp_path / 'out.keys')
    assert KeyRing.load(tmp_path / 'out.keys').keys == [KEY_A, KEY_B]
    with pytest.raises(ValueError, match='object'):
        KeyRing.from_json('[1, 2]')

    merged = KeyRing(sectors={1: {'A': KEY_A}}).merge(KeyRing(keys=[KEY_B], sectors={1: {'A': KEY_B}}))
    assert merged.get(1) == KEY_A and KEY_B in merged.keys


def test_diversify_key():
    uid = '0xD39BC634'
    key = diversify_key(MASTER, uid, sector=1)
    assert len(key) == 6 and key == diversify_key(MASTER, uid, sector=1)
    assert key == diversify_key(MASTER, struct.pack('<L', 0xD39BC634), sector=1)
    assert key == diversify_key(MASTER, 0xD39BC634, sector=1)
    others = {diversify_key(MASTER, uid, sector=2), diversify_key(MASTER, uid, 1, 'B'),
              diversify_key(MASTER, '0xD39BC635', 1), diversify_key(bytes(16), uid, 1)}
    assert key not in others and len(others) == 4
    for kwargs, message in [({'master': b'short'}, '16 bytes'), ({'key_type': 'C'}, 'key_type'),
                            ({'sector': 40}, '0-39'), ({'uid': b'\x00' * 5}, 'uid')]:
        args = {'master': MASTER, 'uid': uid, **kwargs}
        with pytest.raises(ValueError, match=message):
            diversify_key(**args)


# --- reader: trailers, keys, card type ------------------------------------------------

def test_write_block_refuses_unsafe_trailers():
    card = SimulatedCard()
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(1, DEFAULT_KEY)
    with pytest.raises(UnsafeTrailerError, match='write_trailer'):
        reader.write_block(3, KEY_A + bytes.fromhex('FF078169') + KEY_B)
    with pytest.raises(UnsafeTrailerError, match='allow_permanent'):
        reader.write_block(3, KEY_A + AccessBits.build(trailer='permanent').to_bytes() + KEY_B)
    assert card.keys(1) == (DEFAULT_KEY, DEFAULT_KEY)           # nothing written
    reader.write_block(3, build_trailer(KEY_A, KEY_B))          # a safe trailer is fine
    assert card.keys(1) == (KEY_A, KEY_B)


def test_write_trailer_change_keys_and_back():
    card = SimulatedCard()
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(2, DEFAULT_KEY)
    assert reader.read_access() == AccessBits.build()
    reader.write_trailer(KEY_A, KEY_B, AccessBits.build(['write-b', 'value', 'read-only'], 'key-b'))
    assert card.keys(2) == (KEY_A, KEY_B)
    assert str(card.access(2)) == AccessBits.build(['write-b', 'value', 'read-only'], 'key-b').__str__()
    # Key B manages the sector now; Key A may no longer change it.
    reader.authenticate_sector(2, KEY_A)
    with pytest.raises(CardWriteError):
        reader.write_trailer(DEFAULT_KEY, DEFAULT_KEY, AccessBits.build())
    reader.authenticate_sector(2, KEY_B, 'B')
    reader.write_trailer(DEFAULT_KEY, DEFAULT_KEY, AccessBits.build())   # back to a new card
    assert card.keys(2) == (DEFAULT_KEY, DEFAULT_KEY) and card.access(2) == AccessBits.build()


def test_write_trailer_keeps_access_and_checks_input():
    card = SimulatedCard()
    reader = MifareReader.simulated(card)
    with pytest.raises(ValueError, match='authenticate a sector first'):
        reader.write_trailer(KEY_A, KEY_B)
    reader.authenticate_sector(1, DEFAULT_KEY)
    with pytest.raises(ValueError, match='not authenticated'):
        reader.read_access(sector=2)
    reader.write_trailer('A0A1A2A3A4A5', KEY_B, verify=False)
    assert card.read(1, 3)[6:10] == TRANSPORT_ACCESS and card.keys(1)[0] == KEY_A
    reader.authenticate_sector(1, KEY_A)
    with pytest.raises(UnsafeTrailerError):
        reader.write_trailer(KEY_A, KEY_B, AccessBits.build(trailer='frozen'))
    reader.write_trailer(KEY_A, KEY_B, bytes.fromhex('7F078869'))
    assert card.access(1).trailer == '011'


def test_write_trailer_detects_a_trailer_that_did_not_stick(monkeypatch):
    reader = MifareReader.simulated(SimulatedCard())
    reader.authenticate_sector(1, DEFAULT_KEY)
    real_read = reader.read_block
    monkeypatch.setattr(reader, 'read_block', lambda block, raw=False: bytes(6) + TRANSPORT_ACCESS + bytes(6)
                        if block == 3 else real_read(block, raw))
    with pytest.raises(CardWriteError, match='read back'):
        reader.write_trailer(DEFAULT_KEY, DEFAULT_KEY, bytes.fromhex('7F078869'))


def test_open_sector_and_store_keys():
    card = SimulatedCard(keys={4: (KEY_A, KEY_B)})
    card.set_trailer(4, KEY_A, KEY_B, AccessBits.build(trailer='key-b'))
    reader = MifareReader.simulated(card)
    assert reader.open_sector(4, KeyRing(keys=[DEFAULT_KEY, KEY_B])) == ('B', KEY_B)
    assert reader.open_sector(4, [KEY_A]) == ('A', KEY_A)
    assert reader.open_sector(1) == ('A', DEFAULT_KEY)
    assert reader.open_sector(1, DEFAULT_KEY, 'A') == ('A', DEFAULT_KEY)
    with pytest.raises(GNetPlusError):
        reader.open_sector(4, KeyRing())
    with pytest.raises(ValueError, match='no keys'):
        reader.open_sector(4, KeyRing(keys=[]))

    reader.store_keys(KeyRing(sectors={4: {'A': KEY_A, 'B': KEY_B}}))
    reader.authenticate_sector_cached(4, 'B')
    reader.authenticate_sector_cached(1)                     # fallback key stored for other sectors
    reader.store_keys(KeyRing(keys=[], sectors={5: {'A': KEY_A}}), sectors=[5])


def test_open_sector_raises_when_card_is_gone():
    reader = MifareReader.simulated(empty=True)
    with pytest.raises(GNetPlusError):
        reader.open_sector(1, [KEY_A, DEFAULT_KEY])


class _Ultralight(SimulatedReader):
    def _dispatch(self, f, d):
        if f == QueryMessage.REQUEST:
            return b'\x44\x00', []
        return super()._dispatch(f, d)


class _OddSak(SimulatedReader):
    def __init__(self, card, atqa, sak):
        super().__init__(card)
        self.atqa, self.sak = atqa, sak

    def _dispatch(self, f, d):
        if f == QueryMessage.REQUEST:
            return self.atqa, []
        if f == QueryMessage.SELECT_CARD:
            return self.sak, []
        return super()._dispatch(f, d)


def test_card_type():
    assert MifareReader.simulated(SimulatedCard()).card_type() == '1K'
    assert MifareReader.simulated(SimulatedCard(size='4K')).card_type() == '4K'
    assert MifareReader.from_serial(_Ultralight(SimulatedCard())).card_type() == 'Ultralight'
    for atqa, sak, kind in [(b'\x02\x00', b'\x00', '4K'), (b'\x04\x00', b'', '1K'), (b'\x04\x00', b'\x20', 'unknown')]:
        assert MifareReader.from_serial(_OddSak(SimulatedCard(), atqa, sak)).card_type() == kind


# --- simulator: access conditions are enforced ----------------------------------------

def _card_with(sector, data, trailer='key-b', key_a=KEY_A, key_b=KEY_B):
    card = SimulatedCard()
    card.set_trailer(sector, key_a, key_b, AccessBits.build(data, trailer))
    return card


def test_simulator_read_only_and_key_b_blocks():
    card = _card_with(1, ['read-only', 'key-b', 'write-b'])
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(1, KEY_A)
    reader.read_block(0)
    with pytest.raises(CardWriteError):
        reader.write_block(0, bytes(16))
    with pytest.raises(GNetPlusError):          # the card went idle after the refusal
        reader.read_block(0)
    reader.authenticate_sector(1, KEY_A)
    with pytest.raises(CardReadError):
        reader.read_block(1)                     # Key B only
    reader.authenticate_sector(1, KEY_B, 'B')
    reader.write_block(1, b'B' * 16)
    reader.write_block(2, b'C' * 16)
    with pytest.raises(CardWriteError):
        reader.write_block(0, bytes(16))
    assert card.read(1, 1) == b'B' * 16


def test_simulator_value_conditions():
    card = _card_with(1, ['value-decrement', 'value', 'open'])
    reader = MifareReader.simulated(card, value_ops='native')
    card.write(1, 0, bytes.fromhex('E8030000 17FCFFFF E8030000 04FB04FB'.replace(' ', '')))  # 1000
    card.write(1, 1, card.read(1, 0))
    reader.authenticate_sector(1, KEY_A)
    assert reader.read_value(0) == 1000
    reader.decrement_value(0, 250)
    assert card.value(1, 0) == 750
    with pytest.raises(GNetPlusError):
        reader.increment_value(0, 1)             # decrement-only block
    reader.authenticate_sector(1, KEY_A)
    with pytest.raises(GNetPlusError):
        reader.increment_value(1, 1)             # value: increment needs Key B
    reader.authenticate_sector(1, KEY_B, 'B')
    reader.increment_value(1, 5)
    reader.restore(1)
    assert card.value(1, 1) == 1005
    with pytest.raises(CardWriteError):
        reader.create_value_block(0, 1)          # no write on a decrement-only block
    reader.authenticate_sector(1, KEY_B, 'B')
    with pytest.raises((ValueBlockError, GNetPlusError)):
        reader.read_value(2)                     # not a value block


def test_simulator_trailer_reads_and_writes():
    card = SimulatedCard()
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(1, DEFAULT_KEY)
    trailer = reader.read_block(3, raw=True)
    assert trailer[:6] == bytes(6) and trailer[10:] == DEFAULT_KEY     # Key B readable on a new card
    with pytest.raises(NotAuthenticatedError):
        MifareReader.simulated(card).read_block(3)

    managed = _card_with(1, 'open')
    reader = MifareReader.simulated(managed)
    reader.authenticate_sector(1, KEY_A)
    assert reader.read_block(3, raw=True)[10:] == bytes(6)            # Key B hidden
    with pytest.raises(CardWriteError):
        reader.write_block(3, build_trailer(DEFAULT_KEY, KEY_B, trailer='key-b'))   # Key A can't change it
    reader.authenticate_sector(1, KEY_A)
    reader.write_block(3, build_trailer(KEY_A, KEY_B, trailer='key-b'))             # unchanged: allowed

    card = SimulatedCard()
    reader = MifareReader.simulated(card)
    reader.authenticate_sector(1, DEFAULT_KEY, 'B')                    # Key B is readable: no access
    with pytest.raises(CardReadError):
        reader.read_block(0)
    reader.authenticate_sector(1, DEFAULT_KEY, 'B')
    with pytest.raises(CardReadError):
        reader.read_block(3)


def test_simulator_blocks_sector_with_invalid_access_bits():
    card = SimulatedCard()
    card.write(1, 3, DEFAULT_KEY + bytes.fromhex('FF078169') + DEFAULT_KEY)
    assert card.access(1) is None
    reader = MifareReader.simulated(card)
    for op in (lambda: reader.read_block(0), lambda: reader.read_block(3),
               lambda: reader.write_block(0, bytes(16))):
        reader.authenticate_sector(1, DEFAULT_KEY)
        with pytest.raises(GNetPlusError):
            op()
    reader.authenticate_sector(1, DEFAULT_KEY)
    reader.sendmsg(QueryMessage.WRITE_BLOCK, bytes([3]) + DEFAULT_KEY + TRANSPORT_ACCESS + DEFAULT_KEY)
    with pytest.raises(CardWriteError):
        reader.readmsg()


# --- dump and CLI with per-block keys -------------------------------------------------

def test_dump_and_restore_use_the_key_that_may_access_each_block():
    source = _card_with(1, ['open', 'key-b', 'write-b'])
    source.write(1, 1, b'only Key B reads')
    ring = KeyRing(keys=[DEFAULT_KEY], sectors={1: {'A': KEY_A, 'B': KEY_B}})
    dump = read_card(MifareReader.simulated(source), keys=ring)
    assert dump.block(1, 1) == b'only Key B reads'
    assert dump.unread_sectors() == []
    assert read_card(MifareReader.simulated(source), keys=[KEY_A]).block(1, 1) is None

    target = _card_with(1, ['open', 'key-b', 'write-b'])
    assert write_card(MifareReader.simulated(target), dump, keys=ring) == []
    assert target.read(1, 1) == b'only Key B reads'

    locked = _card_with(1, ['read-only', 'open', 'open'])
    with pytest.raises(CardWriteError):
        write_card(MifareReader.simulated(locked), dump, keys=ring, sectors=[1])


@pytest.fixture
def run(monkeypatch, capsys):
    state = {'card': _card_with(1, ['open', 'key-b', 'write-b'])}
    state['card'].write(1, 1, b'secret for B....')
    monkeypatch.setattr(cli, 'open_reader', lambda args: MifareReader.simulated(state['card']))

    def _run(*argv):
        code = cli.main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    _run.state = state
    return _run


def test_cli_access(run):
    code, out, _ = run('access', '1', '--key', KEY_A.hex())
    assert code == 0 and 'Sector 1 (Key A), access bits' in out and 'Block 1 (011, key-b): read: B' in out
    code, out, _ = run('access', '0', '2', '--json')
    rows = [json.loads(line) for line in out.splitlines()]
    assert [r['sector'] for r in rows] == [0, 2] and rows[0]['access'] == 'FF078069'
    assert rows[0]['key_b_readable'] is True
    code, _, err = run('access', '16')
    assert code == 1 and 'does not exist' in err


def test_cli_access_4k_groups_and_undecodable(run):
    run.state['card'] = SimulatedCard(size='4K')
    code, out, _ = run('access', '32')
    assert code == 0 and 'Blocks 10-14' in out
    card = SimulatedCard()
    card.write(1, 3, DEFAULT_KEY + bytes.fromhex('FF078169') + DEFAULT_KEY)
    run.state['card'] = card
    code, out, _ = run('access', '1')
    assert code == 3 and 'refused to read its trailer' in out


def test_cli_access_decode_needs_no_reader(run, monkeypatch):
    monkeypatch.setattr(cli, 'open_reader', lambda args: pytest.fail('no reader needed'))
    code, out, _ = run('access', '--decode', '7F078869')
    assert code == 0 and 'change access bits: B' in out
    code, out, _ = run('access', '--decode', '78778869', '--json')
    assert json.loads(out)['data'] == ['100', '100', '100']
    code, _, err = run('access', '--decode', 'FF078169')
    assert code == 1 and 'invalid' in err
    code, _, err = run('access', '--decode', 'XYZ')
    assert code == 1 and 'access bytes' in err


def test_cli_keys_file_and_per_block_fallback(run, tmp_path):
    keyfile = tmp_path / 'keys.json'
    KeyRing(keys=[], sectors={1: {'A': KEY_A, 'B': KEY_B}}).save(keyfile)
    code, out, _ = run('read', '1', '--keys', str(keyfile))
    assert code == 0 and 'secret for B' in out
    code, out, _ = run('read', '1', '--key', KEY_A.hex())
    assert code == 3 and 'stop every given key' in out
    code, out, _ = run('read', '1', '--key', KEY_A.hex(), '--json')
    assert code == 3 and json.loads(out.splitlines()[1])['data'] is None
    code, out, _ = run('write', '1', '2', '--text', 'B writes', '-y', '--keys', str(keyfile))
    assert code == 0 and run.state['card'].read(1, 2) == b'B writes'.ljust(16, b'\x00')
    code, _, err = run('write', '1', '2', '--text', 'A may not', '-y', '--key', KEY_A.hex())
    assert code == 1 and 'NAK' in err


def test_cli_key_file_errors(run, tmp_path):
    code, _, err = run('read', '1', '--keys', str(tmp_path / 'missing.keys'))
    assert code == 1 and 'Could not read key file' in err
    (tmp_path / 'empty.keys').write_text('# nothing\n')
    code, _, err = run('read', '1', '--keys', str(tmp_path / 'empty.keys'))
    assert code == 1 and 'no keys' in err
    code, _, err = run('read', '1', '--keys', str(tmp_path / 'empty.keys'), '--key', 'A0A1')
    assert code == 1 and '12 hex digits' in err


def test_cli_info_and_read_on_ultralight(run, monkeypatch):
    monkeypatch.setattr(cli, 'open_reader', lambda args: MifareReader.from_serial(_Ultralight(SimulatedCard())))
    code, out, _ = run('info', '--json')
    assert json.loads(out)['card']['type'] == 'Ultralight'
    code, _, err = run('read', '1')
    assert code == 1 and 'Ultralight' in err


def test_simulated_card_set_trailer_takes_access_bits():
    card = SimulatedCard()
    card.set_trailer(5, access=AccessBits.build('read-only', 'key-b'))
    assert card.access(5).data == ('010',) * 3
    assert layout.trailer_block(5) == 3
