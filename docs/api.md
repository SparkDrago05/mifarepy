# API reference

This reference is generated from the docstrings in the source code, so it
always matches the installed version. Everything below can be imported from
the top-level package:

```python
from mifarepy import (
    MifareReader, SectorAuth, CardInfo,
    GNetPlusError, InvalidMessage,
    QueryMessage, ResponseMessage, Message, gencrc,
)
```

## Reader

::: mifarepy.reader.MifareReader
    options:
      heading_level: 3

## Data types

::: mifarepy.protocol.SectorAuth
    options:
      heading_level: 3

::: mifarepy.protocol.CardInfo
    options:
      heading_level: 3

## Card layout

::: mifarepy.layout
    options:
      heading_level: 3
      show_root_heading: true

## Errors

::: mifarepy.protocol.GNetPlusError
    options:
      heading_level: 3

::: mifarepy.protocol.InvalidMessage
    options:
      heading_level: 3

## Low-level protocol

These classes build and parse GNetPlus frames. You only need them to send
commands that `MifareReader` does not wrap. See the
[protocol reference](protocol.md).

::: mifarepy.protocol.Message
    options:
      heading_level: 3

::: mifarepy.protocol.QueryMessage
    options:
      heading_level: 3
      show_if_no_docstring: true

::: mifarepy.protocol.ResponseMessage
    options:
      heading_level: 3

::: mifarepy.protocol.gencrc
    options:
      heading_level: 3
