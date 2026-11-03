# Credits & license

## Maintainer

**Spark Drago** ([@SparkDrago05](https://github.com/SparkDrago05)) designed,
maintains and develops mifarepy.

Contributions are welcome. See the [contributing guide](contributing.md).

## History

mifarepy started in 2025 as a Python 3 port of
[gnetplus](https://github.com/harishpillay/gnetplus), a small Python 2 module
written in 2013 by **Chow Loong Jin** and **Harish Pillay** (Red Hat Inc.) that
read card serial numbers from a PROMAG PCR310U. Since then mifarepy has grown
into a separate library. It adds authentication, block, sector and bulk I/O,
value blocks, event and async support, typed errors and a full test suite.

We thank the original authors for their work, which made this project possible.

## License

mifarepy is free software, released under the
**GNU Lesser General Public License v3.0 or later** (LGPL-3.0-or-later).
You may use it in proprietary applications, but changes to mifarepy itself
must be shared under the same license.

- [`LICENSE`](https://github.com/SparkDrago05/mifarepy/blob/main/LICENSE): the LGPL-3.0 text
- [`COPYING`](https://github.com/SparkDrago05/mifarepy/blob/main/COPYING): the GPL-3.0 text it builds on

The original gnetplus code is Copyright © 2013 Red Hat Inc. and was released
under LGPL-2.1-or-later. Its "or any later version" clause allows it to be
distributed under LGPL-3.0-or-later as part of mifarepy. The original
copyright notice is kept in the source files.

## Trademarks

MIFARE®, MIFARE Classic®, MIFARE Plus® and MIFARE DESFire® are registered
trademarks of NXP B.V. GNetPlus® and PROMAG are trademarks of GIGA-TMS Inc.
mifarepy is an independent project and is not affiliated with or endorsed by
NXP or GIGA-TMS.

Vendor manuals for the readers are available from
[GIGA-TMS](https://www.gigatms.com.tw/). The protocol and card documentation on
this site was written independently for mifarepy.
