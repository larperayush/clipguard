"""
Unit tests for the SQLite storage engine.
"""

import tempfile
from pathlib import Path
from clipguard.storage import StorageManager


def test_storage_add_and_get():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)

        # Add normal item
        id1 = storage.add_entry(
            content="npm run build",
            is_secret=False,
            secret_type=None,
            masked_preview="npm run build",
        )
        assert id1 is not None

        items = storage.get_history()
        assert len(items) == 1
        assert items[0].content == "npm run build"
        assert items[0].is_secret is False


def test_storage_pinning():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)

        id1 = storage.add_entry("docker compose up -d", False, None, "docker compose up -d")
        storage.pin_entry(id1, label="Docker Startup")

        item = storage.get_item(id1)
        assert item is not None
        assert item.is_pinned is True
        assert item.pin_label == "Docker Startup"

        # Check pinned_only filter
        pinned = storage.get_history(pinned_only=True)
        assert len(pinned) == 1

        # Unpin
        storage.unpin_entry(id1)
        item_unpinned = storage.get_item(id1)
        assert item_unpinned.is_pinned is False


def test_storage_purge_secrets():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)

        # Add secret
        id_secret = storage.add_entry(
            content="sk-11112222333344445555666677778888",
            is_secret=True,
            secret_type="OpenAI Key",
            masked_preview="sk-1111****8888",
        )
        # Add normal
        id_normal = storage.add_entry(
            content="echo 'hello world'",
            is_secret=False,
            secret_type=None,
            masked_preview="echo 'hello world'",
        )

        assert len(storage.get_history()) == 2

        # Purge secrets
        purged = storage.purge_secrets()
        assert purged == 1

        remaining = storage.get_history()
        assert len(remaining) == 1
        assert remaining[0].content == "echo 'hello world'"
