# Installation

## Requirements

- **Python 3.9 or newer** (tested on 3.9 – 3.14)
- **pyserial**, installed automatically
- Permission to open the reader's serial port. See [Hardware & setup](hardware.md).

## Install from PyPI

=== "pip"

    ```bash
    pip install mifarepy
    ```

=== "uv"

    ```bash
    uv add mifarepy
    ```

=== "Poetry"

    ```bash
    poetry add mifarepy
    ```

=== "Raspberry Pi"

    Wheels are also published on [piwheels](https://www.piwheels.org/project/mifarepy/),
    so `pip` on Raspberry Pi OS installs without building anything:

    ```bash
    python3 -m venv ~/venvs/rfid && source ~/venvs/rfid/bin/activate
    pip install mifarepy
    ```

## Verify the install

```bash
python -c "import mifarepy; print(mifarepy.__version__)"
```

Then plug in the reader and check that it answers:

```python
from mifarepy import MifareReader

with MifareReader('/dev/ttyUSB0') as reader:   # Windows: 'COM3'
    print(reader.ping(), reader.get_version())
```

## Install from source

```bash
git clone https://github.com/SparkDrago05/mifarepy.git
cd mifarepy
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The `dev` extra adds pytest, coverage, ruff and mypy. To build the
documentation locally, install the `docs` extra and run MkDocs:

```bash
pip install -e ".[docs]"
mkdocs serve
```

## Next steps

- [Hardware & setup](hardware.md): find the serial port and fix permissions
- [Usage guide](usage.md): every feature with examples
- [Examples](examples.md): runnable scripts
