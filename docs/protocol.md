# GNetPlus® protocol reference

GNetPlus is the binary serial protocol used by GIGA-TMS / PROMAG readers.
mifarepy implements it for you. This page is for when you want to know what
goes over the wire: for debugging, writing a driver in another language,
or using a command mifarepy does not wrap yet.

!!! abstract "At a glance"
    - **Physical:** 19200 baud, 8N1, over RS-232, TTL or USB-serial
    - **Model:** host ↔ device query/response; the device may also push events
    - **Framing:** `SOH` header, device address, function code, length, data, CRC-16
    - **Integrity:** CRC-16 with polynomial `0xA001`, preset `0xFFFF`, low byte first

## Frame format

Both directions use the same layout:

| Field | Size | Value |
|---|---|---|
| Header | 1 byte | `SOH` = `0x01` |
| Address | 1 byte | Device address `0`–`255` (`0` reaches any device on a point-to-point link) |
| Function | 1 byte | **Query:** command code. **Response:** `ACK` `0x06`, `NAK` `0x15` or `EVN` `0x12` |
| Length | 1 byte | Number of data bytes, `0`–`255` |
| Data | 0–255 bytes | Command parameters or response payload |
| CRC-16 | 2 bytes | Over *Address … Data*, **low byte first** |

```text
Query     01 | 00 | 24 | 01 | 04 | lo hi        READ BLOCK, block 4
Response  01 | 00 | 06 | 10 | <16 bytes> | lo hi   ACK + block data
Error     01 | 00 | 15 | 01 | 1F | lo hi        NAK: no tag in field
```

### Response types

| Code | Name | Meaning |
|---|---|---|
| `0x06` | **ACK** | Command succeeded. Data holds the result, if any. |
| `0x15` | **NAK** | Command failed. Data holds a one-byte [error code](#error-codes). |
| `0x12` | **EVN** | Unsolicited event, sent while auto mode is on (e.g. card arrived). |

Multi-byte integers in data fields are sent most-significant byte first,
except where a command says otherwise. Card UIDs from anti-collision arrive in
the card's own (little-endian) order. mifarepy normalises them to
`'0xAABBCCDD'`.

### Timing

Leave at least two byte-times of silence after receiving a response before you
send the next query. If a frame stops arriving partway through, discard the
partial buffer.

## CRC-16

The checksum covers every byte from **Address** to the end of **Data**:

```python
def gnetplus_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc  # transmit crc & 0xFF first, then crc >> 8
```

This is the same algorithm as Modbus RTU's CRC-16. mifarepy exposes it as
`mifarepy.gencrc()`.

## Commands

The **mifarepy** column shows which method uses each command.
<span class="mp-no">not wrapped</span> commands are still available through the
low-level `sendmsg()` / `readmsg()` methods (see
[sending raw commands](#sending-raw-commands)).

### Common commands (`0x00`–`0x1F`)

| Code | Command | Query data | ACK data | mifarepy |
|---|---|---|---|---|
| `0x00` | Polling | — | status | `ping()` |
| `0x01` | Get version | — | version string | `get_version()` |
| `0x02` | Set device address | new address | — | <span class="mp-no">not wrapped</span> |
| `0x03` | Logon | password | — | <span class="mp-no">not wrapped</span> |
| `0x04` | Logoff | — | — | <span class="mp-no">not wrapped</span> |
| `0x05` | Set password | new password | — | <span class="mp-no">not wrapped</span> |
| `0x06` | Class name | — | class name | <span class="mp-no">not wrapped</span> |
| `0x07` / `0x08` | Set / get date-time | 7-byte date-time | 7-byte date-time | <span class="mp-no">not wrapped</span> |
| `0x09` / `0x0A` | Get / set register | address (+ data) | register data | <span class="mp-no">not wrapped</span> |
| `0x0B`–`0x10` | Record storage (count, first, next, erase, add, recover) | varies | varies | <span class="mp-no">not wrapped</span> |
| `0x11` / `0x12` | Digital output / input | channel (+ state) | state | <span class="mp-no">not wrapped</span> |
| `0x13` / `0x14` | Analog input / thermometer | channel | value | <span class="mp-no">not wrapped</span> |
| `0x15` | Get node | — | record | <span class="mp-no">not wrapped</span> |
| `0x16` | Get device serial number | — | 4 bytes | <span class="mp-no">not wrapped</span> |
| `0x17` | Silent mode | on/off | on/off | <span class="mp-no">not wrapped</span> |
| `0x19` | Enable auto mode (common) | boolean | result | <span class="mp-no">not wrapped</span> (see `0x3F`) |
| `0x1A` / `0x1C` | Get / set time adjust | (4 bytes) | 4 bytes | <span class="mp-no">not wrapped</span> |
| `0x1B` | Echo | any | same data | <span class="mp-no">not wrapped</span> |
| `0x1D` | Debug | — | debug text | <span class="mp-no">not wrapped</span> |
| `0x1E` | Reset | — | — | <span class="mp-no">not wrapped</span> |
| `0x1F` | Enter firmware update (ISP) | — | — | <span class="mp-no">not wrapped</span> |

Which of these a reader supports depends on its model and firmware. MIFARE
readers typically implement polling, version, address, echo and reset.

### MIFARE commands (`0x20`–`0x3F`)

| Code | Command | Query data | ACK data | mifarepy |
|---|---|---|---|---|
| `0x20` | Request | — | card type (2 bytes) | `get_uid()`, `is_card_present()`, `scan_tag()` |
| `0x21` | Anti-collision | — | UID (4 bytes) | `get_uid()`, `get_uid_int()`, `scan_tag()` |
| `0x22` | Select card | UID (4 bytes) | memory size | `select_card()`, `scan_tag()` |
| `0x23` | Authenticate | key type + sector | — | `authenticate_sector()` |
| `0x24` | Read block | block | 16 bytes | `read_block()`, `read_sector()`, `read_blocks()` |
| `0x25` | Write block | block + 16 bytes | — | `write_block()`, `write_sector()`, `write_blocks()` |
| `0x26` | Set value (with transfer) | block + op + value | — | <span class="mp-no">not wrapped</span> |
| `0x27` | Read value | block | value (4 bytes) | `read_value()` |
| `0x28` | Create value block | block (+ value) | — | `create_value_block()`, `write_value()` |
| `0x29` | Write access conditions | keys + access bits (+ GPB) | — | <span class="mp-no">not wrapped</span> |
| `0x2A` | Halt | — | — | `halt()` |
| `0x2B` | Save key | key type + sector + key | — | `authenticate_sector()` |
| `0x2C` | Get second serial number | — | 4 bytes | `get_second_sn()` (Ultralight) |
| `0x2D` | Read access conditions | — | 5 bytes | <span class="mp-no">not wrapped</span> |
| `0x2E` | Authenticate with stored key | key type + sector | — | `authenticate_sector_cached()` |
| `0x2F` | Request all | — | card type | `request_all()` |
| `0x32` | Set value (without transfer) | block + op + value | — | <span class="mp-no">not wrapped</span> |
| `0x33` | Transfer | block | — | <span class="mp-no">not wrapped</span> |
| `0x34` | Restore | block | — | <span class="mp-no">not wrapped</span> |
| `0x3D` | Get sector by application ID | AID | sector | <span class="mp-no">not wrapped</span> |
| `0x3E` | RF field on/off | `0` / `1` | — | `rf_power()` |
| `0x3F` | Auto mode on/off | `0` / `1` | current mode | `set_auto_mode()` |

Key type codes: **Key A = `0x60`**, **Key B = `0x61`**. Value operation codes:
**increment = `0xC1`**, **decrement = `0xC0`**.

!!! note
    mifarepy's `increment_value()`, `decrement_value()`, `transfer()` and
    `restore()` work by reading the value and writing it back, rather than
    through the `0x26`, `0x32`, `0x33` and `0x34` commands.

## Error codes

When a command fails, the reader replies with `NAK` and a single error byte.
mifarepy raises `GNetPlusError` and fills in `nak_code` and
`code_description`:

| Code | Description in mifarepy | Typical cause |
|---|---|---|
| `0x03` | Empty | No data available |
| `0x04` | Authentication error | Wrong key or key type for the sector |
| `0x09` | Key error | Malformed or missing key |
| `0x0A` | Not authenticated | Block access without authenticating that sector |
| `0x0E` | Transfer error | Value transfer failed |
| `0x0F` | Write error | Write rejected (access conditions or card removed) |
| `0x10` | Increment error | Increment rejected by the card |
| `0x11` | Decrement error | Decrement rejected by the card |
| `0x12` | Read error | Read rejected (access conditions or card removed) |
| `0x1C` | Access timeout | Card did not answer in time |
| `0x1F` | No tag in field | No card on the reader |
| `0x27` | Wrong parameter value | Out-of-range block, sector or argument |
| `0x2D` | Host authentication error | Logon / password required |
| `0x2F` | Wrong DES key | Wrong reader-host DES key |
| `0x33` | DES key load error | Failed to load DES key |
| `0xE0` | Command denied | Not allowed in the current state |
| `0xE1` | Illegal command | Malformed command |
| `0xE2` | Command overrun | Too much data / buffer overrun |
| `0xE3` | Packet CRC error | Corrupted frame: check cabling and baud rate |
| `0xE4` | Out of memory | Address or record out of range |
| `0xE5` | Out of frame | Frame incomplete or too long |
| `0xE6` | Unknown command | Command not supported by this reader |

```python
from mifarepy import GNetPlusError

try:
    reader.authenticate_sector(1, key)
except GNetPlusError as e:
    if e.nak_code == 0x04:
        print('Wrong key for sector 1')
    else:
        print(f'Reader error 0x{e.nak_code:02X}: {e.code_description}')
```

## Events

With auto mode on (`set_auto_mode(True)`), the reader sends `EVN` frames by
itself. mifarepy recognises the card-arrival event (payload `b'I'`), which is
how `wait_for_card()` wakes up. `readmsg(sink_events=True)` skips events while
waiting for a command's response.

## Sending raw commands

Every command code is available on `QueryMessage`. To use one that mifarepy
does not wrap yet:

```python
from mifarepy import MifareReader, QueryMessage

with MifareReader('/dev/ttyUSB0') as reader:
    reader.sendmsg(QueryMessage.ECHO, b'hello')
    reply = reader.readmsg()          # raises GNetPlusError on NAK
    print(reply.data)                 # b'hello'
```

## ASCII mode

Some firmware also accepts a human-readable ASCII form, handy for poking at a
reader from a serial terminal. A frame is `:` followed by hex text (address,
function, length, data) and a carriage return, with no CRC. For example,
`:002000⏎` sends a Request. mifarepy always uses the binary form.
