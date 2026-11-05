# mifarepy -- Python library for MIFARE readers that speak the GNetPlus protocol
# Copyright (C) 2025-2026 Spark Drago <https://github.com/SparkDrago05>
#
# Based on gnetplus (https://github.com/harishpillay/gnetplus)
# Copyright (C) 2013 Red Hat Inc. -- Chow Loong Jin, Harish Pillay
# (originally released under LGPL-2.1-or-later)
#
# This library is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version. See the LICENSE and COPYING files for details.
# SPDX-License-Identifier: LGPL-3.0-or-later

from . import layout
from .protocol import (
    AuthenticationError,
    CardInfo,
    CardReadError,
    CardTimeoutError,
    CardWriteError,
    GNetPlusError,
    InvalidMessage,
    Message,
    NoCardError,
    NotAuthenticatedError,
    QueryMessage,
    ReaderAccessError,
    ReaderConnectionError,
    ReaderNotFoundError,
    ReaderProtocolError,
    ResponseMessage,
    SectorAuth,
    ValueBlockError,
    gencrc,
)
from .reader import MifareReader
from .trace import disable_wire_trace, enable_wire_trace

__version__ = '3.2.0'

__all__ = [
    'AuthenticationError',
    'CardInfo',
    'CardReadError',
    'CardTimeoutError',
    'CardWriteError',
    'GNetPlusError',
    'InvalidMessage',
    'Message',
    'MifareReader',
    'NoCardError',
    'NotAuthenticatedError',
    'QueryMessage',
    'ReaderAccessError',
    'ReaderConnectionError',
    'ReaderNotFoundError',
    'ReaderProtocolError',
    'ResponseMessage',
    'SectorAuth',
    'ValueBlockError',
    '__version__',
    'disable_wire_trace',
    'enable_wire_trace',
    'gencrc',
    'layout',
]
