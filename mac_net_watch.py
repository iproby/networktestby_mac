#!/usr/bin/env python3
"""Compatibility entry point; existing imports and commands keep working."""
from netwatch.core import *  # noqa: F401,F403

if __name__ == "__main__":
    from run import main
    raise SystemExit(main())
