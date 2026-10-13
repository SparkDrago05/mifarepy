# **mifarepy**

[![PyPI Version](https://img.shields.io/pypi/v/mifarepy.svg)](https://pypi.org/project/mifarepy/)
[![Python Versions](https://img.shields.io/pypi/pyversions/mifarepy.svg)](https://pypi.org/project/mifarepy/)
[![PyPI Downloads](https://static.pepy.tech/badge/mifarepy)](https://pepy.tech/projects/mifarepy)
[![License](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/SparkDrago05/mifarepy)](https://github.com/SparkDrago05/mifarepy/issues)
[![Tests](https://github.com/SparkDrago05/mifarepy/actions/workflows/test.yml/badge.svg)](https://github.com/SparkDrago05/mifarepy/actions/workflows/test.yml)

## **Overview**

`mifarepy` is a **Python library** for interfacing with **MIFARE® RFID card readers** (e.g., PROMAG PCR310U, MF5, MF10) using the **GNetPlus® protocol**.
It provides a clean, object-oriented API for performing common operations such as:
- **Interacting via RS232 and USB-serial** interfaces
- **Supporting GNetPlus® commands** (Read, Write, Authenticate, Auto Mode, etc.)
- Reading a card’s serial number (`get_sn`, `wait_for_card`)
- Querying reader firmware version (`get_version`)
- Enabling/disabling automatic card events (`set_auto_mode`, `wait_for_card`)
- Authenticating sectors (`authenticate_sector`)
- Reading and writing 16‑byte blocks (`read_block`, `write_block`)
- Bulk operations on sectors and arbitrary block mappings (`read_sector`, `write_sector`, `read_blocks`, `write_blocks`)

---

## **Attribution & Original Repository**

This project is **derived from** the original `gnetplus.py` which is written in Python 2 by **Chow Loong Jin & Harish Pillay**.

- **Original Repository:** [gnetplus by harishpillay](https://github.com/harishpillay/gnetplus)
- **Original Authors:** Chow Loong Jin & Harish Pillay
- **License:** This project remains under **LGPL v3.0 or later** to comply with the original licensing terms.

This version of `gnetplus.py` includes **bug fixes, more features, documentation improvements, and enhanced compatibility**.

---

## **Supported Hardware**

This library is compatible with **PROMAG** MIFARE® readers, including:

- **PCR310U** (USB-based)
- **MF5 OEM Read/Write Module**
- **MF10 MIFARE Read/Write Module**
- **Other devices using the GNetPlus® protocol**

These readers operate at **13.56 MHz** and support **MIFARE® 1K/4K, Ultra-Light, and PRO cards**.

---

## **Installation**

To install `mifarepy`, ensure **Python 3.6+** is installed, then run:

```sh
pip install mifarepy
```

Or manually include the `mifarepy.py` file in your project.

---

## Quickstart

```python
from mifarepy.reader import MifareReader

# Initialize the reader on your serial port
reader = MifareReader('/dev/ttyUSB0')

# Enable auto mode and wait for card detection
reader.set_auto_mode(True)
card_sn = reader.wait_for_card(timeout=10)
print('Found card:', card_sn)

# Authenticate sector 1 with the default Key A
default_key = bytes.fromhex('FFFFFFFFFFFF')
reader.authenticate_sector(sector=1, key=default_key, key_type='A')

# Read block 4 and display as hex
block_data = reader.read_block(4)
print('Block 4 data:', block_data)

# Write 16 bytes to block 4
payload = bytes(range(16))
reader.write_block(4, payload)
```
---

## **Communicating with the Reader**

### **Detecting the Device**

When plugged into a **Linux** system (such as **Raspberry Pi** or **Fedora**), the reader is detected as:

```
Prolific Technology, Inc. PL2303 Serial Port
```

To find the assigned port, check:

```sh
dmesg | grep ttyUSB
```

Example output:

```
usb 6-1: pl2303 converter now attached to ttyUSB3
```

This means the device is at `/dev/ttyUSB3`.

---

## **Supported Commands**

This library supports the following **GNetPlus® protocol commands**:

| Command               | Functionality                                |
|-----------------------|----------------------------------------------|
| **Polling**           | Check if a reader is connected               |
| **Get Version**       | Retrieve firmware version                    |
| **Logon/Logoff**      | Secure access                                |
| **Get Serial Number** | Retrieve MIFARE® card serial number          |
| **Read Block**        | Read memory block from MIFARE® 1K card       |
| **Write Block**       | Write to a specific block                    |
| **Authenticate**      | Perform authentication with Key A/Key B      |
| **Set Auto Mode**     | Enable/Disable automatic event notifications |
| **Request All**       | Detect multiple cards in the field           |

For a full list of commands, refer to the *
*[mifarepy Communication Protocol](./TM970013_GNetPlusCommunicationProtocol_REV_D.pdf)**.

---

## **Example Output**

When a card is detected, you will see:

```
Found card: 0x19593d65
Tap card again.
Found card: 0x19593d65
```

If no card is found, the script prompts:

```
Tap card again.
```

---

## **MIFARE® 1K Card Structure**

The **MIFARE® 1K card** consists of **16 sectors**, each with **4 blocks** (16 bytes each).  
Memory layout:

- **Blocks 0-3**: Sector 0 (First block stores manufacturer data)
- **Blocks 4-7**: Sector 1
- **Blocks 8-11**: Sector 2
- **...**
- **Blocks 60-63**: Sector 15 (Contains access keys & conditions)

For authentication, use **Key A** or **Key B** stored in the last block of each sector.

---

## **MIFARE® 1K Authentication & Security**

1. **Authenticate** before reading/writing.
2. Use **GNetPlus SAVE_KEY command** to store keys securely.
3. Blocks are **protected** by access conditions.
4. **Keys should not be stored in the same sector** as sensitive data.

For further details, refer to:

- **[MIFARE Application Programming Guide](./TM970014_MifareAppliactionProgrammingGuide_REV_H.pdf)**
- **[MIFARE Demo Quick Start](./TM970018_Mifare%20Demo%20Quick%20Start.pdf)**

---

## **License**

This project is licensed under **GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later)**.  
See [LICENSE](./LICENSE) for the LGPL-3.0 text and [COPYING](./COPYING) for the GPL-3.0 text it builds on.

---

## **Documentation & References**

For more details, refer to:

- **[GNetPlus Communication Protocol](./TM970013_GNetPlusCommunicationProtocol_REV_D.pdf)**
- **[MIFARE Application Guide](./TM970014_MifareAppliactionProgrammingGuide_REV_H.pdf)**
- **[MIFARE RWD Specification](./TM970023_RWD_SPEC.pdf)**
- **[MF10 Instruction Sheet](./TM951179_MF10_Instruction.pdf)**

For further information, visit: [GIGA-TMS Inc.](http://www.gigatms.com.tw)

---

## **Author & Credits**

**Original Authors:**

- **Chow Loong Jin** (<lchow@redhat.com>)
- **Harish Pillay** (<hpillay@redhat.com>)

**Adapted & Maintained by:**

- **Spark Drago** (<https://github.com/SparkDrago05>)

---
