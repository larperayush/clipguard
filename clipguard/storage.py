"""
Storage module for ClipGuard using SQLite.
Stores clipboard history, pinned snippets, and secret metadata with hashing and safety controls.
"""

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, List, Optional


@dataclass
class ClipboardItem:
    id: int
    content: str
    preview: str
    is_secret: bool
    secret_type: Optional[str]
    is_pinned: bool
    pin_label: Optional[str]
    char_count: int
    created_at: str
    last_used_at: str


class StorageManager:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            config_dir = Path.home() / ".clipguard"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(config_dir / "history.db")
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clipboard_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_hash TEXT UNIQUE,
                    content TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    is_secret BOOLEAN NOT NULL DEFAULT 0,
                    secret_type TEXT,
                    is_pinned BOOLEAN NOT NULL DEFAULT 0,
                    pin_label TEXT,
                    char_count INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_content_hash ON clipboard_history(content_hash);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_is_pinned ON clipboard_history(is_pinned);
                """
            )

    @staticmethod
    def hash_content(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def add_entry(
        self,
        content: str,
        is_secret: bool,
        secret_type: Optional[str],
        masked_preview: str,
        store_redacted: bool = False,
    ) -> Optional[int]:
        """
        Inserts or updates a clipboard item.
        If store_redacted is True and item is a secret, stores masked content instead of raw text.
        """
        if not content.strip():
            return None

        content_to_store = masked_preview if (is_secret and store_redacted) else content
        content_hash = self.hash_content(content_to_store)
        preview = masked_preview[:120].replace("\n", " ")
        char_count = len(content)

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM clipboard_history WHERE content_hash = ?",
                (content_hash,),
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE clipboard_history SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (existing["id"],),
                )
                return existing["id"]

            cursor.execute(
                """
                INSERT INTO clipboard_history (
                    content_hash, content, preview, is_secret, secret_type, is_pinned, char_count
                ) VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (content_hash, content_to_store, preview, 1 if is_secret else 0, secret_type, char_count),
            )
            return cursor.lastrowid

    def get_history(
        self,
        limit: int = 30,
        pinned_only: bool = False,
    ) -> List[ClipboardItem]:
        query = "SELECT * FROM clipboard_history"
        params = []
        if pinned_only:
            query += " WHERE is_pinned = 1"
        query += " ORDER BY is_pinned DESC, last_used_at DESC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                ClipboardItem(
                    id=row["id"],
                    content=row["content"],
                    preview=row["preview"],
                    is_secret=bool(row["is_secret"]),
                    secret_type=row["secret_type"],
                    is_pinned=bool(row["is_pinned"]),
                    pin_label=row["pin_label"],
                    char_count=row["char_count"],
                    created_at=row["created_at"],
                    last_used_at=row["last_used_at"],
                )
                for row in rows
            ]

    def search_history(self, term: str, limit: int = 20) -> List[ClipboardItem]:
        pattern = f"%{term}%"
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM clipboard_history
                WHERE content LIKE ? OR preview LIKE ? OR pin_label LIKE ?
                ORDER BY is_pinned DESC, last_used_at DESC LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            ).fetchall()
            return [
                ClipboardItem(
                    id=row["id"],
                    content=row["content"],
                    preview=row["preview"],
                    is_secret=bool(row["is_secret"]),
                    secret_type=row["secret_type"],
                    is_pinned=bool(row["is_pinned"]),
                    pin_label=row["pin_label"],
                    char_count=row["char_count"],
                    created_at=row["created_at"],
                    last_used_at=row["last_used_at"],
                )
                for row in rows
            ]

    def get_item(self, item_id: int) -> Optional[ClipboardItem]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM clipboard_history WHERE id = ?",
                (item_id,),
            ).fetchone()
            if not row:
                return None
            return ClipboardItem(
                id=row["id"],
                content=row["content"],
                preview=row["preview"],
                is_secret=bool(row["is_secret"]),
                secret_type=row["secret_type"],
                is_pinned=bool(row["is_pinned"]),
                pin_label=row["pin_label"],
                char_count=row["char_count"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"],
            )

    def pin_entry(self, item_id: int, label: Optional[str] = None) -> bool:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE clipboard_history SET is_pinned = 1, pin_label = COALESCE(?, pin_label) WHERE id = ?",
                (label, item_id),
            )
            return cursor.rowcount > 0

    def unpin_entry(self, item_id: int) -> bool:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE clipboard_history SET is_pinned = 0 WHERE id = ?",
                (item_id,),
            )
            return cursor.rowcount > 0

    def delete_entry(self, item_id: int) -> bool:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM clipboard_history WHERE id = ?", (item_id,))
            return cursor.rowcount > 0

    def purge_secrets(self) -> int:
        """Purges all entries flagged as secrets that are NOT pinned."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM clipboard_history WHERE is_secret = 1 AND is_pinned = 0"
            )
            return cursor.rowcount

    def clear_all(self, keep_pinned: bool = True) -> int:
        with self._connection() as conn:
            cursor = conn.cursor()
            if keep_pinned:
                cursor.execute("DELETE FROM clipboard_history WHERE is_pinned = 0")
            else:
                cursor.execute("DELETE FROM clipboard_history")
            return cursor.rowcount
