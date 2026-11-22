"""Safe, iterative directory traversal for scanned drives."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field

SKIP_DIRS = {
    "system volume information", "$recycle.bin", ".trashes", ".spotlight-v100", ".fseventsd",
}


@dataclass
class WalkCounters:
    """Thread-safe progress counters."""

    discovered: int = 0
    scanned: int = 0
    skipped: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, name: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + n)

    def snapshot(self) -> tuple[int, int, int]:
        with self._lock:
            return self.discovered, self.scanned, self.skipped


def iter_files(
    root: str, cancel: threading.Event, counters: WalkCounters
) -> Iterator[tuple[str, int]]:
    """Yield ``(path, size)`` for regular files under ``root``.

    Never follows symlinks, scans hidden files (malware hides), skips OS metadata
    directories, tolerates PermissionError and stops promptly when ``cancel`` is set.
    """
    stack = [root]
    while stack and not cancel.is_set():
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if cancel.is_set():
                        return
                    try:
                        if entry.is_symlink():
                            counters.add("skipped")
                        elif entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() not in SKIP_DIRS:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            counters.add("discovered")
                            yield entry.path, entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        counters.add("skipped")
        except OSError:
            counters.add("skipped")
