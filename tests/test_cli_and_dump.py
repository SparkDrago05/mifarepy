"""Tests for mifarepy.dump and the mifarepy command-line tool, using the simulator."""

import json
import subprocess
import sys

import pytest

from mifarepy import MifareReader, cli, layout
from mifarepy.dump import CardDump, detect_size, read_card, total_blocks, write_card
from mifarepy.simulator import SimulatedCard

KEY = b'\xff' * 6
SECRET = bytes.fromhex('A0A1A2A3A4A5')


def filled_card(size='1K', uid='0xD39BC634'):
    card = SimulatedCard(uid=uid, size=size)
    sectors = layout.SECTORS_1K if size == '1K' else layout.SECTORS_4K
    for s in range(sectors):
        for b in layout.data_blocks(s):
            if (s, b) != (0, 0):
                card.write(s, b, bytes([s, b]) * 8)
    return card


# --- library: dump / restore ----------------------------------------------------

@pytest.mark.parametrize('size', ['1K', '4K'])
def test_read_card_reads_everything(size):
    card = filled_card(size)
    dump = read_card(MifareReader.simulated(card))
    assert dump.size == size and dump.uid == card.uid_str
    assert len(dump.blocks) == total_blocks(size)
    assert dump.unread_sectors() == []
    assert dump.block(5, 1) == bytes([5, 1]) * 8
    assert dump.block(5, 3)[:6] == KEY            # Key A filled in, though it reads as zeros
    assert dump.keys[5] == (KEY, KEY)


def test_detect_size():
    assert detect_size(MifareReader.simulated(SimulatedCard(size='1K'))) == '1K'
    assert detect_size(MifareReader.simulated(SimulatedCard(size='4K'))) == '4K'


def test_read_card_with_unknown_key_sector():
    card = filled_card()
    card.set_trailer(2, key_a=SECRET, key_b=SECRET)
    reader = MifareReader.simulated(card)
    dump = read_card(reader)
    assert dump.unread_sectors() == [2]
    assert dump.block(3, 0) == bytes([3, 0]) * 8    # sectors after the failure still read
    dump = read_card(reader, keys=[KEY, SECRET])
    assert dump.unread_sectors() == []
    assert dump.keys[2] == (SECRET, SECRET)


def test_read_card_rejects_bad_key():
    with pytest.raises(ValueError):
        read_card(MifareReader.simulated(), keys=[b'\x01'])


def test_progress_callback():
    calls = []
    read_card(MifareReader.simulated(), progress=lambda i, n, kt: calls.append((i, n, kt)))
    assert calls[0] == (0, 16, 'A') and len(calls) == 16


@pytest.mark.parametrize('ext', ['json', 'bin', 'mfd', 'mct'])
def test_formats_roundtrip(tmp_path, ext):
    card = filled_card()
    card.set_trailer(4, key_a=SECRET, key_b=SECRET)
    dump = read_card(MifareReader.simulated(card))             # sector 4 unreadable
    path = tmp_path / f'card.{ext}'
    dump.save(path)
    loaded = CardDump.load(path)
    assert loaded.uid == dump.uid and loaded.size == '1K'
    assert loaded.block(1, 0) == dump.block(1, 0)
    if ext in ('json', 'mct'):
        assert loaded.unread_sectors() == [4]                   # unread blocks survive
    else:
        assert loaded.block(4, 0) == bytes(16)                  # raw images use zeros


def test_json_keys_and_4k(tmp_path):
    dump = read_card(MifareReader.simulated(filled_card('4K')))
    dump.save(tmp_path / 'c.json')
    loaded = CardDump.load(tmp_path / 'c.json')
    assert loaded.size == '4K' and loaded.keys[39] == (KEY, KEY)
    assert loaded.block(39, 14) == bytes([39, 14]) * 8
    mct = CardDump.from_mct(dump.to_mct())
    assert mct.size == '4K'


def test_dump_validation(tmp_path):
    with pytest.raises(ValueError):
        CardDump('0x0', '2K', [])
    with pytest.raises(ValueError):
        CardDump('0x0', '1K', [None] * 10)
    with pytest.raises(ValueError):
        CardDump('0x0', '1K', [b'short'] + [None] * 63)
    with pytest.raises(ValueError):
        CardDump.from_bin(b'\x00' * 100)
    with pytest.raises(ValueError):
        CardDump.from_json('{"format": "other"}')
    with pytest.raises(ValueError, match='unknown dump format'):
        CardDump.load(tmp_path / 'card.txt')


def test_write_card_copies_data_but_not_trailers_or_block0():
    source = filled_card(uid='0x11111111')
    dump = read_card(MifareReader.simulated(source))
    target = SimulatedCard(uid='0x22222222')
    target.set_trailer(6, key_a=SECRET, key_b=SECRET)
    skipped = write_card(MifareReader.simulated(target), dump)
    assert skipped == [6]                                      # neither FF nor the dump's keys open 6
    assert target.read(1, 2) == bytes([1, 2]) * 8
    assert target.read(0, 0)[:4] != source.read(0, 0)[:4]      # manufacturer block untouched
    assert target.keys(6) == (SECRET, SECRET)                  # trailer untouched


def test_write_card_reports_unopened_sectors():
    dump = read_card(MifareReader.simulated(filled_card()))
    dump.keys.clear()
    target = SimulatedCard()
    target.set_trailer(6, key_a=SECRET, key_b=SECRET)
    assert write_card(MifareReader.simulated(target), dump) == [6]
    assert write_card(MifareReader.simulated(target), dump, keys=[SECRET], sectors=[6]) == []
    assert target.read(6, 0) == bytes([6, 0]) * 8


# --- command-line tool ------------------------------------------------------------

@pytest.fixture
def run(monkeypatch, capsys):
    """Run the CLI against a shared simulated reader; returns (exit_code, stdout, stderr)."""
    state = {'card': filled_card()}

    def fake_open(args):
        return MifareReader.simulated(state['card'])

    monkeypatch.setattr(cli, 'open_reader', fake_open)

    def _run(*argv):
        code = cli.main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    _run.state = state
    return _run


def test_cli_info_scan(run):
    code, out, _ = run('info')
    assert code == 0 and '0xD39BC634' in out and '1K' in out
    code, out, _ = run('scan', '--json')
    assert json.loads(out) == {'uid': '0xD39BC634'}


def test_cli_scan_no_card(run, monkeypatch):
    monkeypatch.setattr(cli, 'open_reader', lambda args: MifareReader.simulated(empty=True))
    code, out, _ = run('scan')
    assert code == 1 and 'No card' in out


def test_cli_read(run):
    code, out, _ = run('read', '2', '--block', '1')
    assert code == 0 and bytes([2, 1]).hex().upper() * 8 in out
    code, out, _ = run('read', '0', '--json')
    rows = [json.loads(line) for line in out.splitlines()]
    assert len(rows) == 4 and rows[3]['trailer'] is True


def test_cli_read_wrong_key_and_bad_sector(run):
    run.state['card'].set_trailer(2, key_a=SECRET, key_b=SECRET)
    code, _, err = run('read', '2')
    assert code == 1 and 'No key opened sector 2' in err
    code, out, _ = run('read', '2', '--key', 'A0A1A2A3A4A5')
    assert code == 0
    code, _, err = run('read', '16')
    assert code == 1 and 'does not exist' in err
    for block in ('4', '-1'):
        code, out, err = run('read', '1', '--block', block)
        assert code == 1 and 'sector 1 has blocks 0-3' in err and out == ''


def test_cli_write(run):
    code, out, _ = run('write', '1', '1', '--text', 'hi there', '--yes')
    assert code == 0 and 'verified' in out
    assert run.state['card'].read(1, 1) == b'hi there'.ljust(16, b'\x00')
    code, _, _ = run('write', '1', '2', '00112233445566778899AABBCCDDEEFF', '-y')
    assert run.state['card'].read(1, 2).hex() == '00112233445566778899aabbccddeeff'


@pytest.mark.parametrize('argv, message', [
    (['write', '1', '3', '00' * 16, '-y'], 'trailer'),
    (['write', '0', '0', '00' * 16, '-y'], 'manufacturer'),
    (['write', '1', '1', 'zz', '-y'], 'hex'),
    (['write', '1', '1', '0011', '-y'], '16 bytes'),
    (['write', '1', '1', '-y'], 'DATA'),
    (['write', '1', '1', '--text', 'x' * 17, '-y'], '16'),
    (['write', '1', '7', '00' * 16, '-y'], 'data blocks 0-2'),
    (['write', '1', '-1', '00' * 16, '-y'], 'data blocks 0-2'),
    (['write', '1', '1', '00' * 16, '-y', '--key', 'FF'], '12 hex'),
    (['write', '1', '1', '00' * 16, '-y', '--key', 'XYZ'], 'not hex'),
])
def test_cli_write_refuses(run, argv, message):
    code, _, err = run(*argv)
    assert code == 1 and message in err


def test_cli_write_needs_confirmation_when_not_interactive(run, monkeypatch):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    code, _, err = run('write', '1', '1', '--text', 'x')
    assert code == 1 and '--yes' in err


def test_cli_write_interactive_confirmation(run, monkeypatch):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda prompt: 'n')
    code, _, err = run('write', '1', '1', '--text', 'x')
    assert code == 1 and 'Cancelled' in err
    monkeypatch.setattr('builtins.input', lambda prompt: 'y')
    assert run('write', '1', '1', '--text', 'x')[0] == 0


def test_cli_dump_and_restore(run, tmp_path):
    path = tmp_path / 'card.json'
    code, out, err = run('dump', str(path))
    assert code == 0 and 'Saved 1K card 0xD39BC634' in out and 'reading sector 16/16' in err
    assert CardDump.load(path).block(7, 2) == bytes([7, 2]) * 8

    run.state['card'] = SimulatedCard(uid='0x0BADCAFE')
    code, out, _ = run('restore', str(path), '--yes')
    assert code == 0 and 'Restored' in out
    assert run.state['card'].read(7, 2) == bytes([7, 2]) * 8


def test_cli_dump_partial_and_bad_files(run, tmp_path):
    run.state['card'].set_trailer(3, key_a=SECRET, key_b=SECRET)
    code, out, _ = run('dump', str(tmp_path / 'c.mct'))
    assert code == 3 and 'sector(s) 3' in out
    code, _, err = run('dump', str(tmp_path / 'c.txt'))
    assert code == 1 and 'unknown dump format' in err
    code, _, err = run('restore', str(tmp_path / 'missing.json'), '-y')
    assert code == 1 and 'Could not read' in err
    run.state['card'].set_trailer(5, key_a=SECRET, key_b=SECRET)
    code, out, _ = run('restore', str(tmp_path / 'c.mct'), '-y', '--sector', '5', '--json')
    assert code == 3 and json.loads(out)['skipped_sectors'] == [5]
    code, out, _ = run('restore', str(tmp_path / 'c.mct'), '-y', '--sector', '3')
    assert code == 0                                           # sector 3 is empty in the dump
    for sector in ('16', '-1'):
        code, _, err = run('restore', str(tmp_path / 'c.mct'), '-y', '--sector', sector)
        assert code == 1 and 'not in the 1K dump (0-15)' in err


def test_write_card_rejects_sector_outside_dump():
    dump = read_card(MifareReader.simulated(filled_card()))
    with pytest.raises(ValueError, match='not in the 1K dump'):
        write_card(MifareReader.simulated(SimulatedCard()), dump, sectors=[20])


def test_cli_watch(run, monkeypatch):
    sim_cards = [SimulatedCard(uid='0x00000001'), None, None, SimulatedCard(uid='0x00000002')]
    reader = MifareReader.simulated(sim_cards[0])
    monkeypatch.setattr(cli, 'open_reader', lambda args: reader)
    step = {'n': 0}

    def fake_sleep(_):
        step['n'] += 1
        nxt = sim_cards[min(step['n'], len(sim_cards) - 1)]
        if nxt is None:
            reader.serial.remove_card()
        elif nxt.uid_str != (reader.serial.card.uid_str if reader.serial.card else None):
            reader.serial.place_card(nxt)

    monkeypatch.setattr(cli.time, 'sleep', fake_sleep)
    code, out, _ = run('watch', '--count', '2', '--json')
    uids = [json.loads(line)['uid'] for line in out.splitlines()]
    assert code == 0 and uids == ['0x00000001', '0x00000002']


def test_cli_trace_and_errors(run, monkeypatch):
    code, _, err = run('scan', '--trace')
    assert code == 0 and 'TX REQUEST' in err

    def boom(args):
        raise cli.ReaderNotFoundError('No MIFARE reader found.')
    monkeypatch.setattr(cli, 'open_reader', boom)
    code, _, err = run('info')
    assert code == 1 and 'No MIFARE reader found' in err


def test_cli_open_reader_choices(monkeypatch):
    args = cli.build_parser().parse_args(['info', '--simulate'])
    assert cli.open_reader(args).port == 'simulated'
    calls = []
    monkeypatch.setattr(cli.MifareReader, 'auto', classmethod(lambda cls: calls.append('auto') or 'R'))
    assert cli.open_reader(cli.build_parser().parse_args(['info'])) == 'R'


def test_cli_version_and_module_entry_point():
    out = subprocess.run([sys.executable, '-m', 'mifarepy', '--version'], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.startswith('mifarepy ')
    out = subprocess.run([sys.executable, '-m', 'mifarepy', 'scan', '--simulate'], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == '0xD39BC634'
