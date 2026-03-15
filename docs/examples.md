# Examples

All example scripts live in the `examples/` directory.  They connect to a real reader
on `/dev/ttyUSB0` and use the factory-default key `FFFFFFFFFFFF`.

Before running any example, ensure the reader is plugged in and you have permission
to access the serial port:

```bash
# Linux: add yourself to the dialout group
sudo usermod -aG dialout $USER   # re-login after this
```

---

## 01 — Card UID

**`examples/01_get_uid.py`**

Demonstrates `get_uid()`, `get_uid_int()`, and `scan_tag()`.

```bash
python examples/01_get_uid.py
```

---

## 02 — Reader info

**`examples/02_reader_info.py`**

Calls `get_version()`, `ping()`, and prints `repr(reader)`.

```bash
python examples/02_reader_info.py
```

---

## 03 — Read sector

**`examples/03_read_sector.py`**

Authenticates sector 1 and reads all three data blocks.  Shows both dict and
combined-string output modes.

```bash
python examples/03_read_sector.py
```

---

## 04 — Write sector

**`examples/04_write_sector.py`**

Writes a test pattern to sector 1 using `write_sector()`, then reads it back to
verify.

```bash
python examples/04_write_sector.py
```

---

## 05 — Multi-sector bulk read

**`examples/05_read_blocks.py`**

Uses `read_blocks()` with the new `auth=` / `SectorAuth` style to read blocks from
multiple sectors in one call.

```bash
python examples/05_read_blocks.py
```

---

## 06 — Value blocks

**`examples/06_value_blocks.py`**

Shows `create_value_block()`, `read_value()`, `increment_value()`,
`decrement_value()`, `transfer()`, and `restore()`.

```bash
python examples/06_value_blocks.py
```

---

## 07 — Write then re-authenticate

**`examples/07_write_reauth.py`**

Demonstrates that `authenticate_sector()` safely re-selects the card after a write,
avoiding the MIFARE IDLE-state NAK bug.

```bash
python examples/07_write_reauth.py
```

---

## 08 — Multi-card anti-collision

**`examples/08_multi_card.py`**

Uses `request_all()`, `select_card()`, and `halt()` to cycle through multiple cards
in the RF field.

```bash
python examples/08_multi_card.py
```

---

## 09 — Async card wait

**`examples/09_async_wait.py`**

Uses `wait_for_card_async()` inside an `asyncio.run()` loop — ideal for non-blocking
integration with FastAPI or Django async views.

```bash
python examples/09_async_wait.py
```
