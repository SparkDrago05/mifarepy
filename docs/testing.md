# Testing without hardware

mifarepy includes a **simulated reader** and **simulated MIFARE Classic
cards**. Your code talks to them exactly as it would to a PROMAG reader, so
you can write tests, run CI and build demos with no hardware attached.

```python
from mifarepy import MifareReader
from mifarepy.simulator import SimulatedCard

card = SimulatedCard(uid='0xD39BC634')       # a blank 1K card, default keys
reader = MifareReader.simulated(card)

print(reader.get_uid())                      # '0xD39BC634'
reader.authenticate_sector(1, bytes.fromhex('FFFFFFFFFFFF'))
reader.write_block(0, b'Hello, mifarepy!')

assert card.read(1, 0) == b'Hello, mifarepy!' # inspect the card directly
```

## pytest fixtures

Installing mifarepy registers a pytest plugin with three fixtures:

| Fixture | What it is |
|---|---|
| `mifare_card` | A blank MIFARE Classic 1K `SimulatedCard` with factory-default keys |
| `mifare_simulator` | A `SimulatedReader` with `mifare_card` in its field |
| `mifare_reader` | A `MifareReader` connected to `mifare_simulator`, closed after the test |

```python title="test_badges.py"
from mifarepy import NoCardError
import pytest

from myapp import read_employee_id   # your code, which takes a MifareReader


def test_reads_employee_id(mifare_reader, mifare_card):
    mifare_card.write(1, 0, b'EMP-000042'.ljust(16, b'\x00'))
    assert read_employee_id(mifare_reader) == 42


def test_no_card(mifare_reader, mifare_simulator):
    mifare_simulator.remove_card()
    with pytest.raises(NoCardError):
        read_employee_id(mifare_reader)
```

Override a fixture to start from a different card:

```python
import pytest
from mifarepy.simulator import SimulatedCard


@pytest.fixture
def mifare_card():
    return SimulatedCard(uid='0x11223344', size='4K')
```

## Designing your code for tests

Pass the reader into your functions instead of opening it inside them. Then
production code uses the real reader and tests use the simulated one:

```python
def read_employee_id(reader: MifareReader) -> int:
    reader.authenticate_sector(1, KEY)
    return int(reader.read_block(0, raw=True)[4:10])


if __name__ == '__main__':
    with MifareReader.auto() as reader:
        print(read_employee_id(reader))
```

## Working with simulated cards

```python
from mifarepy.simulator import SimulatedCard

card = SimulatedCard(uid='0x01020304', size='4K')

card.write(5, 0, b'\x11' * 16)                 # set block 0 of sector 5
card.read(5, 0)                                # read it back
card.set_trailer(2, key_a=bytes.fromhex('A0A1A2A3A4A5'), key_b=b'\xff' * 6)
card.keys(2)                                   # (key_a, key_b)
card.value(3, 1)                               # value-block content, or None
card.uid_str                                   # '0x01020304'
```

The simulator is available as `reader.serial` (or the `mifare_simulator`
fixture):

```python
sim = reader.serial
sim.remove_card()                              # take the card away
sim.place_card(SimulatedCard(uid='0xCAFEBABE')) # tap a new one (sends an event in auto mode)
sim.queries                                    # every command received, for assertions
```

`place_card()` is thread-safe, so a test can tap a card while another
thread is blocked in `wait_for_card()`:

```python
import threading

threading.Timer(0.2, sim.place_card, args=(SimulatedCard(),)).start()
uid = reader.wait_for_card(timeout=3)
```

## What the simulator models

| Modelled | Not modelled (yet) |
|---|---|
| Card presence, request / anti-collision / select, HALT, RF power | Access-condition rules beyond keys |
| Key A / Key B authentication, failures drop the card to idle | Firmware quirks of specific reader models |
| Block reads and writes relative to the authenticated sector; Key A reads as zeros | MIFARE Ultralight, Plus and DESFire |
| 1K and 4K layouts, including the 16-block sectors 32–39 | Timing |
| Value blocks: create, read, increment, decrement, restore, transfer | |
| Auto mode with card-arrival events, polling, version, echo | |

!!! warning "Always test on real hardware before shipping"
    The simulator follows the protocol documentation. Real readers can differ:
    the 3.1.1 release fixed a firmware arithmetic bug that only showed up on a
    real PCR310U. Use the simulator for fast tests and CI, and run your key
    flows on a real reader before a release.
