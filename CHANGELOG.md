# Changelog

All notable changes to mifarepy are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `increment_value()` / `decrement_value()` no longer send SET_VALUE (`0x26`)
  in the default `value_ops='auto'` mode; they use read-modify-write again.
  Tested on a PROMAG PCR310U with firmware `PGM0487 V1.4R0`, SET_VALUE drops
  bit 7 of each delta byte and loses carries (1000 + 250 gave 866), and some
  decrements are rejected with NAK `0x06`. In 3.1.0 the wrong value stayed on
  the card until the read-back check rewrote it. SET_VALUE is still used with
  `value_ops='native'`. `transfer()` / `restore()` keep using native
  RESTORE + TRANSFER, which work correctly on that firmware.
- `wait_for_card()` now honours `timeout`. Before, it blocked forever on a
  serial port opened without a read timeout (the default) if no card arrived.
  It also enables auto mode only after checking for a card: on PGM0487
  V1.4R0 a REQUEST that finds no card stopped insert events, so a card
  tapped afterwards was never seen.
  `wait_for_card_async()` no longer truncates fractional timeouts.
- `get_version()` strips the trailing NUL that PGM0487 firmware appends.

## [3.1.0] - 2026-11-03

### Added
- Native value-block arithmetic: `increment_value()` / `decrement_value()` use
  the reader's SET_VALUE command, and `transfer()` / `restore()` use
  RESTORE + TRANSFER. This means decrement-only value blocks (access bits
  `001`) now work. Every result is verified by reading the block back.
- `MifareReader(value_ops=...)`: `'auto'` (default; native with automatic
  fallback to read-modify-write if the reader rejects the commands or the
  result is unexpected), `'native'` or `'software'` (previous behaviour).
- `mifarepy.layout`: helpers for MIFARE Classic 1K/4K block arithmetic
  (`blocks_in_sector`, `data_blocks`, `trailer_block`, `absolute_block`,
  `sector_of`, `is_trailer`).
- `SECURITY.md`, `llms.txt`, coverage badge, CI on Windows and macOS.

### Changed
- `read_sector()`, `write_sector()` and `write_sector_uniform()` follow the
  layout of the most recently authenticated sector (or `sector=`), so the
  15 data blocks of 4K sectors 32–39 are handled. 1K behaviour is unchanged.
- `write_sector()` accepts any multiple of 16 bytes up to the sector's data
  size, and validates dict keys before writing anything.
- Docs are versioned per release (`3.0.1`, `3.0.0`, …) with `latest` as the
  default, and unreleased docs live under `dev`.

## [3.0.1] - 2026-11-03

### Fixed
- NAK error descriptions now follow the vendor error-code table. Several codes
  were mislabelled before: `0x04` is an authentication error (was "Invalid
  address"), `0x1F` means no tag in the field, and `0xE0`–`0xE6` are GNetPlus
  framing errors. `GNetPlusError.code_description` changes accordingly;
  `nak_code` and `raw` are unchanged.
- `wait_for_card()` is annotated as returning `str` and accepting a `float`
  timeout (it raises `TimeoutError` rather than returning `None`).
- Use `serial.is_open` instead of the deprecated `isOpen()`.
- Docstring for `authenticate_sector_cached()` named the wrong SAVE_KEY opcode.

### Changed
- README rewritten: correct Python 3.9+ requirement, accurate feature and
  hardware lists, links to the documentation.
- Documentation rebuilt: new GNetPlus protocol reference, MIFARE Classic
  primer, hardware & troubleshooting guide and credits page replace the links
  to vendor PDFs; the API reference is generated from docstrings.
- Docstrings converted to Google style; full license headers with SPDX IDs.
- CI tests Python 3.9–3.14 and runs ruff, mypy and coverage.

### Added
- `__all__` in the package root, `AUTHORS.md`, this changelog, and `dev` /
  `docs` optional dependency groups.

## [3.0.0] - 2026-06-04

A developer-experience overhaul of the API, plus a test suite, runnable
examples, a documentation site and CI.

### Added
- `get_uid()` returns the UID as `'0xAABBCCDD'` (always little-endian);
  `get_uid_int()` returns it as an unsigned 32-bit integer.
- `scan_tag()` runs REQUEST, ANTI_COLLISION and SELECT in one call and returns
  a `CardInfo` (`uid`, `uid_int`, `uid_bytes`).
- `ping()` and `is_card_present()` return a bool without raising.
- `SectorAuth` for per-sector authentication settings, accepted by
  `read_blocks(auth=...)` and `write_blocks(auth=...)`.
- `authenticate_sector_cached()` authenticates with a key already stored in
  the reader (AUTHENTICATE_KEY, `0x2E`).
- `write_sector_uniform()`, an explicit helper for writing the same 16 bytes
  to a whole sector.
- `InvalidMessage.raw_bytes` and `GNetPlusError.nak_code` for error context.
- Type hints (`py.typed`) and `@overload` on `read_block()`.
- pytest suite, nine examples, MkDocs documentation site, CI.

### Fixed
- `read_sector()` no longer inserts a separator when joining blocks.

### Deprecated
- `get_sn()` emits a `DeprecationWarning`; use `get_uid()` or `get_uid_int()`.

## [2.0] - 2025-06-15

### Added
- `MifareReader` class for card operations.
- Custom timeouts for reader responses.
- Low-level send/receive API (`sendmsg()` / `readmsg()`) for advanced use.
- `DummySerial` test helper and an expanded offline test suite.

### Changed
- **Breaking:** `Handle` renamed to `MifareReader`.
- **Breaking:** `Card.read_block()` renamed to `read_sector()`.
- Code restructured into the `mifarepy/` package; packaging via
  `pyproject.toml` only.
- Versioned documentation on GitHub Pages.

## [1.0.3] - 2025-03-21

### Changed
- Documentation migrated to MkDocs (Material theme) and published on
  GitHub Pages: installation, usage, API reference and contributing guides.
- Packaging moved from `setup.py` to a PEP 621 `pyproject.toml`.
  No library code changes.

## [1.0.2] - 2025-03-15

First stable release on PyPI, renamed from `pymifare` to `mifarepy`.

### Added
- Python 3 port of gnetplus: GNetPlus protocol framing and CRC, reading card
  serial numbers over USB or RS-232 serial.

[3.1.0]: https://github.com/SparkDrago05/mifarepy/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/SparkDrago05/mifarepy/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/SparkDrago05/mifarepy/compare/v2.0...v3.0.0
[2.0]: https://github.com/SparkDrago05/mifarepy/compare/v1.0.3...v2.0
[1.0.3]: https://github.com/SparkDrago05/mifarepy/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/SparkDrago05/mifarepy/releases/tag/v1.0.2
