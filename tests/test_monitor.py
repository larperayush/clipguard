"""
Unit tests for the ClipboardWatcher daemon and ephemeral timer.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from clipguard.monitor import ClipboardWatcher
from clipguard.storage import StorageManager


def test_watcher_process_safe_clip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)
        watcher = ClipboardWatcher(storage=storage)

        watcher.process_clip("echo 'hello safe code'")
        history = storage.get_history()
        assert len(history) == 1
        assert history[0].is_secret is False


def test_watcher_process_secret_with_purge():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)
        watcher = ClipboardWatcher(storage=storage, auto_purge=True)

        with patch("pyperclip.copy") as mock_copy:
            watcher.process_clip("AKIAIOSFODNN7EXAMPLE")
            # Should have called copy("") to wipe
            mock_copy.assert_called_with("")

        history = storage.get_history()
        assert len(history) == 1
        assert history[0].is_secret is True


def test_watcher_process_secret_timed_expire():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageManager(db_path=db_path)
        watcher = ClipboardWatcher(storage=storage, timeout=1)

        with patch("pyperclip.paste", return_value="AKIAIOSFODNN7EXAMPLE"), \
             patch("pyperclip.copy") as mock_copy:
            watcher._expire_clipboard("AKIAIOSFODNN7EXAMPLE", wait_seconds=0.1)
            mock_copy.assert_called_with("")
