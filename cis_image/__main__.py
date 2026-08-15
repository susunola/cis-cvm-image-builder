"""Enable ``python -m cis_image``."""

from __future__ import annotations

import sys

from cis_image import main

if __name__ == "__main__":
    sys.exit(main())
