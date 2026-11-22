"""Tamper-evident audit log (Week 6): a SHA-256 hash chain plus HMAC, stored in SQLite.

``chain_hash = SHA256(prev_hash || canonical_json(event))`` links every record to the one
before it, so editing or deleting a record in the middle breaks every later hash. The HMAC
(keyed with a server secret) stops someone without the secret from simply recomputing a
consistent chain after editing. Honest limit: this is tamper-*evident*, not tamper-proof:
truncating the newest records is not detectable from the chain alone (see CRYPTO_DESIGN.md).

The same database also keeps intel enrichments so signed reports can include final verdicts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical_json(obj: Any) -> str:
    """Sorted keys, no whitespace: the byte-exact form that gets hashed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class VerifyOutcome:
    valid: bool
    length: int
    broken_at: int | None


class AuditChain:
    """Append-only chained log. ``lock`` lets callers keep append + publish atomic."""

    def __init__(self, db_path: Path | str, secret: str) -> None:
        if not secret:
            raise ValueError("audit chain needs a non-empty HMAC secret")
        self._secret = secret.encode()
        self.lock = threading.RLock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._backup: dict[int, str] = {}
        with self.lock, self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_log(
                    idx INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, scan_id TEXT NOT NULL,
                    payload TEXT NOT NULL, prev_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL, hmac TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS audit_scan ON audit_log(scan_id);
                CREATE TABLE IF NOT EXISTS enrichments(
                    file_event_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS enrich_scan ON enrichments(scan_id);
                """
            )
        with self.lock:
            row = self._db.execute(
                "SELECT idx, chain_hash FROM audit_log ORDER BY idx DESC LIMIT 1"
            ).fetchone()
        self._last_idx, self._last_hash = (row[0], row[1]) if row else (0, GENESIS)

    # ---- chain ----------------------------------------------------------------------------
    def _mac(self, chain_hash: str) -> str:
        return hmac.new(self._secret, chain_hash.encode(), hashlib.sha256).hexdigest()

    def append(self, event: dict[str, Any]) -> tuple[int, str]:
        """Add one event (a FILE_SCANNED payload without chain fields). Returns (index, hash)."""
        payload = canonical_json(event)
        with self.lock:
            idx = self._last_idx + 1
            chain_hash = hashlib.sha256((self._last_hash + payload).encode()).hexdigest()
            with self._db:
                self._db.execute(
                    "INSERT INTO audit_log VALUES(?,?,?,?,?,?,?)",
                    (idx, event["event_id"], event["scan_id"], payload, self._last_hash,
                     chain_hash, self._mac(chain_hash)),
                )
            self._last_idx, self._last_hash = idx, chain_hash
            return idx, chain_hash

    def verify(self) -> VerifyOutcome:
        """Recompute the whole chain; report the first index that does not check out."""
        with self.lock:
            rows = self._db.execute(
                "SELECT idx, payload, prev_hash, chain_hash, hmac FROM audit_log ORDER BY idx"
            ).fetchall()
        prev, count = GENESIS, 0
        for idx, payload, prev_hash, chain_hash, mac in rows:
            count += 1
            recomputed = hashlib.sha256((prev + payload).encode()).hexdigest()
            ok = (
                idx == count
                and prev_hash == prev
                and recomputed == chain_hash
                and hmac.compare_digest(mac, self._mac(chain_hash))
            )
            if not ok:
                return VerifyOutcome(False, len(rows), count)
            prev = chain_hash
        return VerifyOutcome(True, len(rows), None)

    # ---- queries --------------------------------------------------------------------------
    def length(self) -> int:
        with self.lock:
            return self._last_idx

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self._db.execute(
                "SELECT payload, idx, chain_hash FROM audit_log WHERE event_id=?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        return {**json.loads(row[0]), "chain_index": row[1], "chain_hash": row[2]}

    def events_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self._db.execute(
                "SELECT payload, idx, chain_hash FROM audit_log WHERE scan_id=? ORDER BY idx",
                (scan_id,),
            ).fetchall()
        return [{**json.loads(p), "chain_index": i, "chain_hash": h} for p, i, h in rows]

    def save_enrichment(self, file_event_id: str, scan_id: str, payload: str) -> None:
        with self.lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO enrichments VALUES(?,?,?)",
                (file_event_id, scan_id, payload),
            )

    def enrichments_for_scan(self, scan_id: str) -> dict[str, dict[str, Any]]:
        with self.lock:
            rows = self._db.execute(
                "SELECT file_event_id, payload FROM enrichments WHERE scan_id=?", (scan_id,)
            ).fetchall()
        return {fid: json.loads(p) for fid, p in rows}

    # ---- demo-only tampering --------------------------------------------------------------
    def tamper(self, idx: int | None = None) -> int | None:
        """Silently flip one stored record's tier to SAFE (what an attacker hiding a detection
        would do). Returns the edited index, or None when the log is empty."""
        with self.lock:
            n = self._last_idx
            if n == 0:
                return None
            idx = idx or max(1, n // 2)
            row = self._db.execute("SELECT payload FROM audit_log WHERE idx=?", (idx,)).fetchone()
            if row is None:
                return None
            original = row[0]
            data = json.loads(original)
            data["tier"] = "SAFE" if data.get("tier") != "SAFE" else "CRITICAL"
            self._backup.setdefault(idx, original)
            with self._db:
                self._db.execute(
                    "UPDATE audit_log SET payload=? WHERE idx=?", (canonical_json(data), idx)
                )
            return idx

    def undo_tamper(self) -> bool:
        """Restore records edited by ``tamper`` (keeps rehearsals repeatable)."""
        with self.lock:
            if not self._backup:
                return False
            with self._db:
                for idx, original in self._backup.items():
                    self._db.execute("UPDATE audit_log SET payload=? WHERE idx=?", (original, idx))
            self._backup.clear()
            return True

    def close(self) -> None:
        with self.lock:
            self._db.close()
