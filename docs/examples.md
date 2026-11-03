# Examples

Nine runnable scripts live in the
[`examples/`](https://github.com/SparkDrago05/mifarepy/tree/main/examples)
folder. Each one takes the serial port as an optional argument (default
`/dev/ttyUSB0`) and uses the factory-default key `FFFFFFFFFFFF`:

```bash
python examples/01_basic_uid.py /dev/ttyUSB0     # Windows: COM3
```

!!! warning "Use a spare card"
    Examples 04–07 and 09 **write** to the card. They never touch sector
    trailers, but they will overwrite data blocks.

<div class="grid cards" markdown>

-   __01 — Basic card UID__

    ---

    Reads the UID three ways and prints the reader's firmware version.

    `ping()` · `get_version()` · `get_uid()` · `get_uid_int()` · `scan_tag()`

    [:octicons-file-code-24: `01_basic_uid.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/01_basic_uid.py)

-   __02 — Event mode__

    ---

    Turns on auto mode and waits for the reader to announce a card.

    `wait_for_card()`

    [:octicons-file-code-24: `02_event_mode.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/02_event_mode.py)

-   __03 — Async wait__

    ---

    Waits for a card without blocking an asyncio event loop. This is the
    pattern for FastAPI and other async services.

    `wait_for_card_async()`

    [:octicons-file-code-24: `03_async_wait.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/03_async_wait.py)

-   __04 — Read & write a block__

    ---

    Runs the full authenticate → read → write → verify cycle on one 16-byte block.

    `authenticate_sector()` · `read_block()` · `write_block()`

    [:octicons-file-code-24: `04_read_write_block.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/04_read_write_block.py)

-   __05 — Sector operations__

    ---

    Reads and writes all three data blocks of a sector in one call.

    `read_sector()` · `write_sector()`

    [:octicons-file-code-24: `05_sector_operations.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/05_sector_operations.py)

-   __06 — Multi-sector bulk I/O__

    ---

    Reads and writes blocks across several sectors, each with its own key.

    `read_blocks()` · `write_blocks()` · `SectorAuth`

    [:octicons-file-code-24: `06_multi_sector_bulk.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/06_multi_sector_bulk.py)

-   __07 — Value blocks__

    ---

    Creates a stored-value counter, then increments, decrements, transfers
    and restores it.

    `create_value_block()` · `increment_value()` · `decrement_value()` · `transfer()` · `restore()`

    [:octicons-file-code-24: `07_value_blocks.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/07_value_blocks.py)

-   __08 — Multi-card enumeration__

    ---

    Lists every card on the reader using HALT and REQUEST ALL.

    `get_uid()` · `halt()` · `request_all()`

    [:octicons-file-code-24: `08_multi_card.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/08_multi_card.py)

-   __09 — RF power cycling__

    ---

    Recovers a stuck card by switching the RF field off and on, inside a retry loop.

    `rf_power()` · `authenticate_sector()` · `read_block()`

    [:octicons-file-code-24: `09_rf_power_reset.py`](https://github.com/SparkDrago05/mifarepy/blob/main/examples/09_rf_power_reset.py)

</div>

## 01 — Basic card UID

```bash
python examples/01_basic_uid.py
```

## 02 — Event mode

```bash
python examples/02_event_mode.py
```

## 03 — Async wait

```bash
python examples/03_async_wait.py
```

## 04 — Read and write a block

```bash
python examples/04_read_write_block.py
```

## 05 — Sector operations

```bash
python examples/05_sector_operations.py
```

## 06 — Multi-sector bulk I/O

```bash
python examples/06_multi_sector_bulk.py
```

## 07 — Value blocks

```bash
python examples/07_value_blocks.py
```

## 08 — Multi-card enumeration

```bash
python examples/08_multi_card.py
```

## 09 — RF power cycling

```bash
python examples/09_rf_power_reset.py
```
