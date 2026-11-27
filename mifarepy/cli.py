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

"""The ``mifarepy`` command-line tool.

```text
mifarepy info                     reader port, firmware and the card on it
mifarepy scan [--wait 10]         print the UID of the card on the reader
mifarepy watch                    print each card as it is tapped (Ctrl+C to stop)
mifarepy read [SECTOR ...]        show blocks (all sectors by default)
mifarepy write SECTOR BLOCK DATA  write one data block (hex, or --text)
mifarepy dump FILE                save the whole card (.json, .bin, .mfd, .mct)
mifarepy restore FILE             write a saved dump's data blocks back
mifarepy access [SECTOR ...]      explain who may read, write and change each block
mifarepy access --decode HEX      explain access bytes without a reader
```

Global options: ``--port`` (default: find the reader automatically),
``--simulate`` (use the built-in simulator, no hardware), ``--trace`` (print
every frame), ``--key HEX`` (repeatable; default FFFFFFFFFFFF), ``--keys FILE``
(a key list or JSON key file).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any, Callable, Optional, Sequence

from . import __version__, layout
from .access import AccessBits, UnsafeTrailerError
from .dump import CardDump, _with_fallback, read_card, write_card
from .keys import KeyRing, parse_key
from .protocol import GNetPlusError, InvalidMessage, NoCardError, ReaderConnectionError, ReaderNotFoundError
from .reader import MifareReader
from .trace import disable_wire_trace, enable_wire_trace

DEFAULT_KEY = 'FFFFFFFFFFFF'


class CliError(Exception):
    """A user-facing error: printed without a traceback, exit code 1."""


# -- helpers ---------------------------------------------------------------------

def _keys(args: argparse.Namespace) -> KeyRing:
    """The keys from --key and --keys FILE (default: FFFFFFFFFFFF)."""
    ring = KeyRing(keys=[])
    for path in args.keys or []:
        try:
            ring = ring.merge(KeyRing.load(path))
        except (OSError, ValueError) as exc:
            raise CliError(f'Could not read key file {path}: {exc}') from None
    for text in args.key or []:
        try:
            bytes.fromhex(text)
        except ValueError:
            raise CliError(f'--key {text!r} is not hex') from None
        try:
            ring.add(parse_key(text))
        except ValueError:
            raise CliError(f'--key {text!r} must be 12 hex digits (6 bytes)') from None
    if not args.key and not args.keys:
        ring.add(DEFAULT_KEY)
    if not len(ring):
        raise CliError('the key files hold no keys')
    return ring


def _ascii(data: bytes) -> str:
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def _out(args: argparse.Namespace, text: str, record: Optional[dict[str, Any]] = None) -> None:
    if args.json:
        print(json.dumps(record if record is not None else {'message': text}), flush=True)
    else:
        print(text, flush=True)


def _confirm(args: argparse.Namespace, question: str) -> None:
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise CliError(f'{question} Re-run with --yes to confirm.')
    answer = input(f'{question} [y/N] ').strip().lower()
    if answer not in ('y', 'yes'):
        raise CliError('Cancelled.')


def _demo_card() -> Any:
    from .simulator import SimulatedCard

    card = SimulatedCard(uid='0xD39BC634')
    card.write(1, 0, b'Hello, mifarepy!')
    return card


def open_reader(args: argparse.Namespace) -> MifareReader:
    """Open the reader the global options describe. Tests replace this."""
    if args.simulate:
        return MifareReader.simulated(_demo_card())
    if args.port:
        return MifareReader(args.port)
    return MifareReader.auto()


def _open_sector(reader: MifareReader, sector: int, keys: KeyRing,
                 key_type: Optional[str]) -> tuple[str, bytes]:
    types = [key_type] if key_type else ['A', 'B']
    candidates = keys.candidates(sector, key_type)
    last: Optional[GNetPlusError] = None
    for kt, key in candidates:
        try:
            reader.authenticate_sector(sector, key, kt)
            return kt, key
        except NoCardError:
            raise
        except GNetPlusError as exc:
            last = exc
    raise CliError(f'No key opened sector {sector}. Pass the right one with --key or --keys '
                   f'(tried {len(candidates)} key(s) as Key {" and ".join(types)}).') from last


# -- commands --------------------------------------------------------------------

def cmd_info(reader: MifareReader, args: argparse.Namespace) -> int:
    version = reader.get_version()
    record: dict[str, Any] = {'port': reader.port, 'firmware': version, 'card': None}
    lines = [f'Reader:   {reader.port}', f'Firmware: {version}']
    try:
        kind = reader.card_type()
        uid = reader.get_uid()
        record['card'] = {'uid': uid, 'type': kind, 'size': kind if kind in ('1K', '4K') else None}
        label = {'1K': 'MIFARE Classic 1K', '4K': 'MIFARE Classic 4K', 'Ultralight': 'MIFARE Ultralight'}
        lines.append(f'Card:     {uid} ({label.get(kind, "unknown type")})')
    except NoCardError:
        lines.append('Card:     none on the reader')
    _out(args, '\n'.join(lines), record)
    return 0


def cmd_scan(reader: MifareReader, args: argparse.Namespace) -> int:
    try:
        uid = reader.wait_for_card(timeout=args.wait) if args.wait else reader.get_uid()
    except (NoCardError, TimeoutError):
        _out(args, 'No card on the reader.', {'uid': None})
        return 1
    _out(args, uid, {'uid': uid})
    return 0


def cmd_watch(reader: MifareReader, args: argparse.Namespace) -> int:
    if not args.json:
        print('Waiting for cards (Ctrl+C to stop)...', file=sys.stderr, flush=True)
    last: Optional[str] = None
    absent = 0
    seen = 0
    while args.count is None or seen < args.count:
        try:
            uid = reader.get_uid()
        except GNetPlusError:
            absent += 1
            if absent >= 2:          # gone for two polls in a row: forget it
                last = None
            time.sleep(args.interval)
            continue
        absent = 0
        if uid != last:
            last = uid
            seen += 1
            stamp = datetime.now().isoformat(timespec='seconds')
            _out(args, f'{stamp}  {uid}', {'time': stamp, 'uid': uid})
        time.sleep(args.interval)
    return 0


def cmd_read(reader: MifareReader, args: argparse.Namespace) -> int:
    keys = _keys(args)
    size = _classic_size(reader)
    count = layout.SECTORS_1K if size == '1K' else layout.SECTORS_4K
    sectors = args.sectors or list(range(count))
    for sector in sectors:
        if not 0 <= sector < count:
            raise CliError(f'sector {sector} does not exist on a {size} card (0-{count - 1})')
        if args.block is not None and not 0 <= args.block < layout.blocks_in_sector(sector):
            raise CliError(f'sector {sector} has blocks 0-{layout.trailer_block(sector)}')
    records: list[dict[str, Any]] = []
    refused = 0
    for sector in sectors:
        opened = _open_sector(reader, sector, keys, args.key_type)
        candidates = keys.candidates(sector, args.key_type)
        blocks = [args.block] if args.block is not None else list(range(layout.blocks_in_sector(sector)))
        if not args.json:
            print(f'Sector {sector} (Key {opened[0]})')
        for rel in blocks:
            def read(rel: int = rel) -> bytes:
                return reader.read_block(rel, raw=True)
            data, opened, _ = _with_fallback(reader, sector, opened, candidates, read)
            trailer = layout.is_trailer(sector, rel)
            records.append({'sector': sector, 'block': rel, 'data': data.hex().upper() if data else None,
                            'trailer': trailer})
            if args.json:
                print(json.dumps(records[-1]))
            elif data is None:
                refused += 1
                print(f'  {rel:>2}  (the access bits stop every given key from reading this block)')
            else:
                note = '  (trailer: Key A | access bits | Key B)' if trailer else f'  {_ascii(data)}'
                print(f'  {rel:>2}  {data.hex().upper()}{note}')
    return 0 if not refused and all(r['data'] for r in records) else 3


def _parse_data(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        raw = args.text.encode('utf-8')
        if len(raw) > 16:
            raise CliError(f'--text is {len(raw)} bytes; a block holds 16')
        return raw.ljust(16, b'\x00')
    if args.data is None:
        raise CliError('give DATA as 32 hex digits, or use --text')
    try:
        data = bytes.fromhex(args.data)
    except ValueError:
        raise CliError('DATA must be hex, e.g. 00112233445566778899AABBCCDDEEFF') from None
    if len(data) != 16:
        raise CliError(f'DATA must be exactly 16 bytes (32 hex digits), got {len(data)}')
    return data


def cmd_write(reader: MifareReader, args: argparse.Namespace) -> int:
    data = _parse_data(args)
    sector, block = args.sector, args.block
    if not 0 <= sector < layout.SECTORS_4K:
        raise CliError('sector must be 0-39')
    if block < 0:
        raise CliError(f'sector {sector} has data blocks 0-{layout.trailer_block(sector) - 1}')
    if layout.is_trailer(sector, block):
        raise CliError(f'Block {block} is the trailer of sector {sector} (keys and access bits). '
                       'The CLI never writes trailers: a mistake there can lock the sector for good.')
    if sector == 0 and block == 0:
        raise CliError('Block 0 of sector 0 is the read-only manufacturer block.')
    if block >= layout.trailer_block(sector):
        raise CliError(f'sector {sector} has data blocks 0-{layout.trailer_block(sector) - 1}')
    uid = reader.get_uid()
    _confirm(args, f'Write {data.hex().upper()} to sector {sector}, block {block} of card {uid}?')
    keys = _keys(args)
    opened = _open_sector(reader, sector, keys, args.key_type)

    def write() -> bytes:
        reader.write_block(block, data)
        return data
    done, opened, error = _with_fallback(reader, sector, opened, keys.candidates(sector, args.key_type), write)
    if done is None and error is not None:
        raise error
    written = reader.read_block(block, raw=True)
    if written != data:
        raise CliError(f'Verification failed: block reads back as {written.hex().upper()}')
    _out(args, f'Wrote and verified sector {sector}, block {block}.',
         {'sector': sector, 'block': block, 'data': data.hex().upper(), 'verified': True})
    return 0


def _progress(args: argparse.Namespace, verb: str) -> Optional[Callable[[int, int, Optional[str]], None]]:
    if args.json:
        return None

    def report(i: int, total: int, key_type: Optional[str]) -> None:
        state = f'Key {key_type}' if key_type else 'no key worked'
        print(f'  {verb} sector {i + 1}/{total}: {state}', file=sys.stderr, flush=True)
    return report


def cmd_dump(reader: MifareReader, args: argparse.Namespace) -> int:
    dump = read_card(reader, keys=_keys(args), size=args.size, progress=_progress(args, 'reading'))
    try:
        dump.save(args.file)
    except ValueError as exc:
        raise CliError(str(exc)) from None
    unread = dump.unread_sectors()
    msg = f'Saved {dump.size} card {dump.uid} to {args.file}'
    if unread:
        msg += f'\nWarning: no key opened sector(s) {", ".join(map(str, unread))}; their blocks are empty in the file.'
    _out(args, msg, {'uid': dump.uid, 'size': dump.size, 'file': args.file, 'unread_sectors': unread})
    return 0 if not unread else 3


def cmd_restore(reader: MifareReader, args: argparse.Namespace) -> int:
    try:
        dump = CardDump.load(args.file)
    except (OSError, ValueError, KeyError) as exc:
        raise CliError(f'Could not read {args.file}: {exc}') from None
    for sector in args.sectors or []:
        if not 0 <= sector < dump.sectors:
            raise CliError(f'sector {sector} is not in the {dump.size} dump (0-{dump.sectors - 1})')
    uid = reader.get_uid()
    target = f'card {uid}' + ('' if uid == dump.uid else f' (the dump is from {dump.uid})')
    _confirm(args, f'Write the data blocks of {args.file} to {target}? '
                   'Trailers and the manufacturer block are not written.')
    skipped = write_card(reader, dump, keys=_keys(args), sectors=args.sectors,
                         progress=_progress(args, 'writing'))
    msg = f'Restored {args.file} to {uid}.'
    if skipped:
        msg += f'\nWarning: no key opened sector(s) {", ".join(map(str, skipped))}; they were not written.'
    _out(args, msg, {'uid': uid, 'file': args.file, 'skipped_sectors': skipped})
    return 0 if not skipped else 3


def _access_record(sector: Optional[int], bits: AccessBits) -> dict[str, Any]:
    return {'sector': sector, 'access': str(bits), 'data': list(bits.data), 'trailer': bits.trailer,
            'gpb': f'{bits.gpb:02X}', 'permanent': bits.is_permanent, 'key_b_readable': bits.key_b_readable}


def _print_access(args: argparse.Namespace, title: str, sector: Optional[int], bits: AccessBits,
                  per_group: int) -> None:
    if args.json:
        print(json.dumps(_access_record(sector, bits)), flush=True)
        return
    print(title)
    for line in bits.describe(per_group).splitlines():
        print(f'  {line}')


def cmd_decode(args: argparse.Namespace) -> int:
    try:
        raw = bytes.fromhex(args.decode)
        bits = AccessBits.from_bytes(raw)
    except UnsafeTrailerError as exc:
        raise CliError(str(exc)) from None
    except ValueError:
        raise CliError('--decode takes the access bytes (6 or 8 hex digits, e.g. FF078069) '
                       'or a whole 32-digit trailer') from None
    _print_access(args, f'Access bits {bits}', None, bits, 1)
    return 0


def cmd_access(reader: MifareReader, args: argparse.Namespace) -> int:
    keys = _keys(args)
    size = _classic_size(reader)
    count = layout.SECTORS_1K if size == '1K' else layout.SECTORS_4K
    sectors = args.sectors or list(range(count))
    for sector in sectors:
        if not 0 <= sector < count:
            raise CliError(f'sector {sector} does not exist on a {size} card (0-{count - 1})')
    problems = 0
    for sector in sectors:
        key_type, _ = _open_sector(reader, sector, keys, args.key_type)
        try:
            raw = reader.read_block(layout.trailer_block(sector), raw=True)
            bits = AccessBits.from_bytes(raw)
        except (GNetPlusError, UnsafeTrailerError) as exc:
            problems += 1
            what = (f'access bytes {raw[6:9].hex().upper()} are invalid' if isinstance(exc, UnsafeTrailerError)
                    else 'the card refused to read its trailer')
            msg = (f'Sector {sector}: {what}. Key {key_type} may not read the access bits, '
                   'or the sector is blocked by invalid access bits.')
            _out(args, msg, {'sector': sector, 'access': None, 'error': msg})
            continue
        per_group = 1 if layout.blocks_in_sector(sector) == 4 else 5
        _print_access(args, f'Sector {sector} (Key {key_type}), access bits {bits}', sector, bits, per_group)
    return 0 if not problems else 3


def _classic_size(reader: MifareReader) -> str:
    kind = reader.card_type()
    if kind == 'Ultralight':
        raise CliError('This is a MIFARE Ultralight card; this command works on MIFARE Classic cards.')
    return '4K' if kind == '4K' else '1K'


# -- argument parsing ----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group('reader options')
    g.add_argument('--port', help='serial port, e.g. /dev/ttyUSB0 or COM3 (default: find the reader)')
    g.add_argument('--simulate', action='store_true', help='use the built-in simulated reader and card')
    g.add_argument('--trace', action='store_true', help='print every frame sent and received (keys hidden)')
    g.add_argument('--json', action='store_true', help='print JSON lines instead of text')

    keyed = argparse.ArgumentParser(add_help=False)
    k = keyed.add_argument_group('key options')
    k.add_argument('--key', action='append', metavar='HEX',
                   help=f'key to try, 12 hex digits; repeat for several (default {DEFAULT_KEY})')
    k.add_argument('--keys', action='append', metavar='FILE',
                   help='key file: one hex key per line (.keys, .dic, .txt) or JSON with per-sector '
                        'keys; repeat for several')
    k.add_argument('--key-type', choices=['A', 'B'], help='only try this key type (default: A, then B)')

    confirm = argparse.ArgumentParser(add_help=False)
    confirm.add_argument('-y', '--yes', action='store_true', help='do not ask for confirmation')

    parser = argparse.ArgumentParser(
        prog='mifarepy',
        description='Read, write and manage MIFARE Classic cards on PROMAG / GNetPlus readers.',
        epilog='Docs: https://sparkdrago05.github.io/mifarepy/latest/cli/',
    )
    parser.add_argument('--version', action='version', version=f'mifarepy {__version__}')
    sub = parser.add_subparsers(dest='command', metavar='COMMAND', required=True)

    sub.add_parser('info', parents=[common], help='show the reader and the card on it')

    p = sub.add_parser('scan', parents=[common], help='print the UID of the card on the reader')
    p.add_argument('--wait', type=float, metavar='SECONDS', help='wait up to SECONDS for a card')

    p = sub.add_parser('watch', parents=[common], help='print each card as it is tapped')
    p.add_argument('--interval', type=float, default=0.25, metavar='SECONDS', help='poll interval (default 0.25)')
    p.add_argument('--count', type=int, help='stop after this many cards')

    p = sub.add_parser('read', parents=[common, keyed], help='show blocks of one or more sectors')
    p.add_argument('sectors', nargs='*', type=int, metavar='SECTOR', help='sectors to read (default: all)')
    p.add_argument('--block', type=int, help='only this block (relative to the sector)')

    p = sub.add_parser('write', parents=[common, keyed, confirm], help='write one data block')
    p.add_argument('sector', type=int)
    p.add_argument('block', type=int, help='block number relative to the sector')
    p.add_argument('data', nargs='?', help='16 bytes as 32 hex digits')
    p.add_argument('--text', help='write this text (up to 16 bytes, zero-padded) instead of hex DATA')

    p = sub.add_parser('dump', parents=[common, keyed], help='save the whole card to a file')
    p.add_argument('file', help='output file: .json, .bin, .mfd or .mct')
    p.add_argument('--size', choices=['1K', '4K'], help='card size (default: detect)')

    p = sub.add_parser('restore', parents=[common, keyed, confirm], help="write a dump's data blocks to the card")
    p.add_argument('file', help='dump file: .json, .bin, .mfd or .mct')
    p.add_argument('--sector', dest='sectors', type=int, action='append', metavar='N',
                   help='only restore this sector; repeat for several')

    p = sub.add_parser('access', parents=[common, keyed],
                       help='explain who may read, write and change each block')
    p.add_argument('sectors', nargs='*', type=int, metavar='SECTOR', help='sectors to show (default: all)')
    p.add_argument('--decode', metavar='HEX',
                   help='explain these access bytes (e.g. FF078069) without a reader or card')
    return parser


COMMANDS: dict[str, Callable[[MifareReader, argparse.Namespace], int]] = {
    'info': cmd_info, 'scan': cmd_scan, 'watch': cmd_watch, 'read': cmd_read,
    'write': cmd_write, 'dump': cmd_dump, 'restore': cmd_restore, 'access': cmd_access,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI. Returns the exit code (0 ok, 1 error, 2 usage, 3 partial, 130 interrupted)."""
    args = build_parser().parse_args(argv)
    trace = enable_wire_trace() if args.trace else None
    reader: Optional[MifareReader] = None
    try:
        if getattr(args, 'decode', None):
            return cmd_decode(args)
        reader = open_reader(args)
        return COMMANDS[args.command](reader, args)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except (CliError, GNetPlusError, InvalidMessage, ReaderConnectionError, ReaderNotFoundError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass
        if trace is not None:
            disable_wire_trace(trace)


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
