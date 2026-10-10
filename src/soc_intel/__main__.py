"""Execution entrypoint when invoking `python -m soc_intel`."""

import sys
from soc_intel.cli import main

if __name__ == "__main__":
    sys.exit(main())
