#!/usr/bin/env python3
"""Regenerate docs/COURSE_MAPPING.md from backend/app/course_map.py (run from anywhere)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.course_map import REPO_ROOT, render_markdown  # noqa: E402

if __name__ == "__main__":
    target = REPO_ROOT / "docs" / "COURSE_MAPPING.md"
    target.write_text(render_markdown(), encoding="utf-8")
    print(f"wrote {target}")
