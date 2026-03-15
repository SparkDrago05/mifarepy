# mifarepy examples

Each script is self-contained and demonstrates a specific feature.
Run any of them directly after installing mifarepy and connecting a reader.

| Script | What it shows |
|---|---|
| [01_basic_uid.py](01_basic_uid.py) | Poll for a card UID via REQUEST+ANTI_COLLISION |
| [02_event_mode.py](02_event_mode.py) | Enable auto mode, block waiting for a card-insert EVN |
| [03_async_wait.py](03_async_wait.py) | Non-blocking card detection inside an `asyncio` loop |
| [04_read_write_block.py](04_read_write_block.py) | Authenticate sector, read and write a single 16-byte block |
| [05_sector_operations.py](05_sector_operations.py) | Read and write all data blocks in a sector at once |
| [06_multi_sector_bulk.py](06_multi_sector_bulk.py) | `read_blocks` / `write_blocks` across multiple sectors in one call |
| [07_value_blocks.py](07_value_blocks.py) | Create a value block, increment, decrement, transfer, restore |
| [08_multi_card.py](08_multi_card.py) | HALT then REQUEST_ALL to enumerate multiple cards in field |
| [09_rf_power_reset.py](09_rf_power_reset.py) | Cycle RF field off/on to reset a stuck card |

## Quick start

```bash
pip install mifarepy

# adjust port if needed
python examples/01_basic_uid.py /dev/ttyUSB0
```

All scripts accept an optional positional argument for the serial port
(default: `/dev/ttyUSB0` on Linux, `COM3` on Windows).
