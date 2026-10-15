#!/usr/bin/env python3
"""InjectorKit entry point.

    python injectorkit.py ssrf -h

Each vulnerability class is a subcommand. See README.md for the design.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from injectorkit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
