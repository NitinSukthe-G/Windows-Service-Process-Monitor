"""Backward-compatible launcher: same as `python agent/monitor.py --watch`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.monitor import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["--watch", *sys.argv[1:]]))
