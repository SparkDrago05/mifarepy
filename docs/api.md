# API reference

This reference is generated from the docstrings in the source code, so it
always matches the installed version. Everything below can be imported from
the top-level package:

```python
from mifarepy import (
    MifareReader, SectorAuth, CardInfo, layout,
    GNetPlusError, AuthenticationError, NoCardError, InvalidMessage,  # and the other errors below
    ReaderConnectionError, ReaderNotFoundError,
    enable_wire_trace, disable_wire_trace,
    QueryMessage, ResponseMessage, Message, gencrc,
)
from mifarepy.simulator import SimulatedCard, SimulatedReader
from mifarepy.discovery import find_ports
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

Reader NAKs raise a subclass of `GNetPlusError`; see
[error handling](usage.md#error-handling) for which code raises which.

::: mifarepy.protocol.GNetPlusError
    options:
      heading_level: 3

::: mifarepy.protocol.NoCardError
    options:
      heading_level: 3

::: mifarepy.protocol.AuthenticationError
    options:
      heading_level: 3

::: mifarepy.protocol.NotAuthenticatedError
    options:
      heading_level: 3

::: mifarepy.protocol.CardReadError
    options:
      heading_level: 3

::: mifarepy.protocol.CardWriteError
    options:
      heading_level: 3

::: mifarepy.protocol.ValueBlockError
    options:
      heading_level: 3

::: mifarepy.protocol.CardTimeoutError
    options:
      heading_level: 3

::: mifarepy.protocol.ReaderProtocolError
    options:
      heading_level: 3

::: mifarepy.protocol.ReaderAccessError
    options:
      heading_level: 3

::: mifarepy.protocol.ReaderConnectionError
    options:
      heading_level: 3

::: mifarepy.protocol.ReaderNotFoundError
    options:
      heading_level: 3

::: mifarepy.protocol.error_for_nak
    options:
      heading_level: 3

::: mifarepy.protocol.InvalidMessage
    options:
      heading_level: 3

## Finding readers

::: mifarepy.discovery
    options:
      heading_level: 3
      show_root_heading: true

## Simulator

See [Testing without hardware](testing.md) for a guide.

::: mifarepy.simulator.SimulatedCard
    options:
      heading_level: 3

::: mifarepy.simulator.SimulatedReader
    options:
      heading_level: 3
      members: [place_card, remove_card]

## Frame tracing

::: mifarepy.trace.enable_wire_trace
    options:
      heading_level: 3

::: mifarepy.trace.disable_wire_trace
    options:
      heading_level: 3

::: mifarepy.trace.format_frame
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
