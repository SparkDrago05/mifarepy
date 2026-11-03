# Hardware & setup

## Supported readers

mifarepy talks to readers made by GIGA-TMS Inc. (sold under the **PROMAG**
brand) that implement the GNetPlus® protocol and its MIFARE command set:

| Reader | Form factor | Connection |
|---|---|---|
| **PCR310U** | Desktop reader | USB, via a built-in Prolific PL2303 USB-serial bridge |
| **MF5** | OEM module | RS-232 / TTL serial |
| **MF10** | OEM module | RS-232 / TTL serial |

All of them run at **13.56 MHz** (ISO/IEC 14443 Type A). mifarepy's API covers
**MIFARE Classic 1K and 4K** cards. The hardware can also detect MIFARE
Ultralight cards. `get_second_sn()` reads the Ultralight's second serial-number
part, but there is no Ultralight read/write API yet.

Serial settings are fixed by the reader firmware: **19200 baud, 8 data bits,
no parity, 1 stop bit**. `MifareReader` uses these by default.

## Find the serial port

=== "Linux"

    Plug the reader in and check the kernel log:

    ```bash
    sudo dmesg | grep -i -E "pl2303|ttyUSB"
    ```

    ```text
    usb 1-1: New USB device found, idVendor=067b, idProduct=2303
    pl2303 1-1:1.0: pl2303 converter detected
    usb 1-1: pl2303 converter now attached to ttyUSB0
    ```

    The reader is at `/dev/ttyUSB0`. You can also list ports from Python:

    ```bash
    python -m serial.tools.list_ports -v
    ```

=== "Windows"

    Open **Device Manager → Ports (COM & LPT)**. The reader shows up as
    *Prolific USB-to-Serial Comm Port (COM3)* or similar. Use that name:

    ```python
    MifareReader('COM3')
    ```

    If it shows a yellow warning icon, install the current Prolific PL2303
    driver from Windows Update or the Prolific website.

=== "macOS"

    Recent macOS versions include a PL2303 driver. Look for the device with:

    ```bash
    ls /dev/cu.usbserial*
    ```

    and pass that path, e.g. `MifareReader('/dev/cu.usbserial-1410')`.

## Permissions (Linux)

Serial devices belong to the `dialout` group (`uucp` on Arch). Add your user
once, then log out and back in:

```bash
sudo usermod -aG dialout "$USER"
```

### Stable device name (optional)

`/dev/ttyUSB0` can change when you plug in other USB-serial devices. A udev
rule gives the reader a fixed name:

```bash title="/etc/udev/rules.d/99-promag.rules"
SUBSYSTEM=="tty", ATTRS{idVendor}=="067b", ATTRS{idProduct}=="2303", SYMLINK+="promag", GROUP="dialout", MODE="0660"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Now use `MifareReader('/dev/promag')`.

!!! note
    Many USB-serial adapters use the same PL2303 chip. If you have several,
    match on `ATTRS{serial}` as well.

## Reading range and placement

- Hold the card flat against the reader. The usable range is a few centimetres.
- Metal surfaces and phones next to the card reduce the range.
- Several cards in the field at once are fine. See
  [example 08](examples.md#08-multi-card-enumeration).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `RuntimeError: Unable to open port` | Wrong port name or no permission | Check the port as above. On Linux, join the `dialout` group. |
| `InvalidMessage` / timeouts on every call | Another program has the port open, or the wrong baud rate | Close other serial tools and keep the default 19200 baud |
| `GNetPlusError: No tag in field` (NAK `0x1F`) | No card on the reader | Place the card flat on the reader, or wait with `wait_for_card()` |
| `GNetPlusError: Authentication error` (NAK `0x04`) | Wrong key or key type for that sector | Check the key and Key A/B. See the [primer](mifare-classic.md#keys-and-authentication). |
| `GNetPlusError: Not authenticated` (NAK `0x0A`) | Read/write before authenticating, or a different sector | Call `authenticate_sector()` for the sector you access |
| Card stops responding after an aborted transaction | Card state machine is stuck | Cycle the RF field with `rf_power(False)` / `rf_power(True)`. See [example 09](examples.md#09-rf-power-cycling). |
| Spurious events after reconnecting | Auto mode was left on | `close()` turns auto mode off. Call `set_auto_mode(False)` if you crashed before closing. |

The full list of reader error codes is in the
[protocol reference](protocol.md#error-codes).
