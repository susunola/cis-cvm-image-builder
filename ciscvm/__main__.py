"""Enable ``python -m ciscvm``."""

from __future__ import annotations

import sys

from ciscvm import main

if __name__ == "__main__":
    sys.exit(main())
