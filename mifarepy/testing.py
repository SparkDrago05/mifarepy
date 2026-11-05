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

"""pytest fixtures for testing code that uses mifarepy, without hardware.

Installed automatically as a pytest plugin with mifarepy. In your tests:

```python
def test_reads_badge(mifare_reader, mifare_card):
    mifare_card.write(1, 0, b'EMPLOYEE-000042\\x00')
    assert read_employee_id(mifare_reader) == 42


def test_no_card(mifare_reader, mifare_simulator):
    mifare_simulator.remove_card()
    assert not mifare_reader.is_card_present()
```

Fixtures:

- ``mifare_card``: a blank MIFARE Classic 1K `SimulatedCard` (default keys).
- ``mifare_simulator``: a `SimulatedReader` with ``mifare_card`` in its field.
- ``mifare_reader``: a `MifareReader` connected to ``mifare_simulator``.
"""

from __future__ import annotations

from typing import Iterator

import pytest

from .reader import MifareReader
from .simulator import SimulatedCard, SimulatedReader


@pytest.fixture
def mifare_card() -> SimulatedCard:
    """A blank MIFARE Classic 1K card with factory-default keys."""
    return SimulatedCard()


@pytest.fixture
def mifare_simulator(mifare_card: SimulatedCard) -> SimulatedReader:
    """A simulated GNetPlus reader with ``mifare_card`` in the field."""
    return SimulatedReader(mifare_card)


@pytest.fixture
def mifare_reader(mifare_simulator: SimulatedReader) -> Iterator[MifareReader]:
    """A `MifareReader` connected to ``mifare_simulator``; closed after the test."""
    reader = MifareReader.from_serial(mifare_simulator)
    yield reader
    reader.close()
