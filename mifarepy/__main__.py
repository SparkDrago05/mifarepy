"""Allow ``python -m mifarepy``."""

import sys

from .cli import main

sys.exit(main())
