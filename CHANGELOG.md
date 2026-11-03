# Changelog

All notable changes to mifarepy are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

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

See the [GitHub release](https://github.com/SparkDrago05/mifarepy/releases/tag/v3.0.0).

## [2.0] - 2025-06-15

## [1.0.3] - 2025-03-21

## [1.0.2] - 2025-03-15

[3.0.1]: https://github.com/SparkDrago05/mifarepy/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/SparkDrago05/mifarepy/compare/v2.0...v3.0.0
[2.0]: https://github.com/SparkDrago05/mifarepy/compare/v1.0.3...v2.0
[1.0.3]: https://github.com/SparkDrago05/mifarepy/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/SparkDrago05/mifarepy/releases/tag/v1.0.2
