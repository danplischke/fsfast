"""Shared setup for the compliance suites (see ``tests/compliance/run.sh``)."""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(__file__)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
