#!/usr/bin/env python
"""Generate safe synthetic observability data.  Usage: python scripts/generate_demo_events.py [-n 150] [--reset]"""
import argparse
import os
import sys
from pathlib import Path

os.environ.setdefault("OBSERVABILITY_LOG_LEVEL", "CRITICAL")  # keep demo output quiet
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.observability.demo import generate_demo_data  # noqa: E402
from backend.observability.service import get_service  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=150, help="number of synthetic requests")
    ap.add_argument("--hours", type=float, default=6.0, help="spread over the last N hours")
    ap.add_argument("--reset", action="store_true", help="clear existing data first")
    a = ap.parse_args()
    svc = get_service()
    if a.reset:
        svc.repo.clear_all()
    generate_demo_data(svc, a.n, a.hours)
    print(f"Generated {a.n} synthetic requests -> {svc.settings.db_url}")
    print(svc.summary())


if __name__ == "__main__":
    main()
