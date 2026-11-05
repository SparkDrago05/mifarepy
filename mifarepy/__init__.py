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
    CardInfo,
    GNetPlusError,
    InvalidMessage,
    Message,
    QueryMessage,
    ResponseMessage,
    SectorAuth,
    gencrc,
)
from .reader import MifareReader

__version__ = '3.1.1'

__all__ = [
    'CardInfo',
    'GNetPlusError',
    'InvalidMessage',
    'Message',
    'MifareReader',
    'QueryMessage',
    'ResponseMessage',
    'SectorAuth',
    '__version__',
    'gencrc',
    'layout',
]
