"""
Clipboard monitoring daemon.
Watches system clipboard for new entries, triggers security inspections, and handles safety actions.
"""

import threading
import time
from typing import Optional
import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clipguard.detector import detect_secrets
from clipguard.storage import StorageManager

console = Console()


class ClipboardWatcher:
    def __init__(
        self,
        storage: Optional[StorageManager] = None,
        auto_purge: bool = False,
        store_redacted: bool = False,
        poll_interval: float = 0.5,
        timeout: int = 0,
    ):
        self.storage = storage or StorageManager()
        self.auto_purge = auto_purge
        self.store_redacted = store_redacted
        self.poll_interval = poll_interval
        self.timeout = timeout
        self._last_content: Optional[str] = None

    def start(self):
        timeout_desc = f"[bold green]{self.timeout}s[/bold green]" if self.timeout > 0 else "[dim]Disabled[/dim]"
        console.print(
            Panel.fit(
                "[bold cyan]🛡️ ClipGuard Watcher Active[/bold cyan]\n"
                f"[dim]Auto-Purge Secrets:[/dim] [{'bold red]ENABLED[/bold red]' if self.auto_purge else '[yellow]DISABLED[/yellow]'}\n"
                f"[dim]Store Redacted Only:[/dim] [{'bold green]YES[/bold green]' if self.store_redacted else '[yellow]NO[/yellow]'}\n"
                f"[dim]Auto-Expire Timer:[/dim] {timeout_desc}\n"
                "[dim]Press Ctrl+C to stop monitoring.[/dim]",
                border_style="cyan",
            )
        )

        try:
            # Seed initial clipboard so we don't treat existing content as new
            try:
                self._last_content = pyperclip.paste()
            except Exception:
                self._last_content = ""

            while True:
                time.sleep(self.poll_interval)
                try:
                    current_content = pyperclip.paste()
                except Exception:
                    continue

                if current_content != self._last_content:
                    self._last_content = current_content
                    self.process_clip(current_content)

        except KeyboardInterrupt:
            console.print("\n[yellow]Watcher stopped by user.[/yellow]")

    def _expire_clipboard(self, original_secret: str, wait_seconds: int):
        time.sleep(wait_seconds)
        try:
            current = pyperclip.paste()
            if current == original_secret:
                pyperclip.copy("")
                self._last_content = ""
                console.print(
                    f"\n[bold green]🔒 Auto-Expire ({wait_seconds}s): Sensitive secret wiped from clipboard buffer![/bold green]"
                )
        except Exception:
            pass

    def process_clip(self, content: str):
        if not content or not content.strip():
            return

        result = detect_secrets(content)

        if result.is_secret:
            matches_summary = ", ".join({m.secret_type for m in result.matches})

            # Print warning box
            grid = Table.grid(expand=True)
            grid.add_column(justify="left")
            grid.add_row(f"[bold red]⚠️ SECRET LEAK DETECTED![/bold red]")
            grid.add_row(f"[yellow]Detected:[/yellow] [bold white]{matches_summary}[/bold white]")
            grid.add_row(f"[dim]Masked Preview:[/dim] [cyan]{result.masked_content[:80]}[/cyan]...")

            if self.auto_purge:
                # Wipe clipboard immediately
                pyperclip.copy("")
                self._last_content = ""
                grid.add_row("[bold red]Action:[/bold red] [strike]Clipboard purged immediately![/strike]")
                console.print(Panel(grid, border_style="red", title="SECURITY ALERT"))
            elif self.timeout > 0:
                grid.add_row(
                    f"[bold cyan]⏳ Ephemeral Window:[/bold cyan] Secret accessible for [bold]{self.timeout}s[/bold], then auto-wiped."
                )
                console.print(Panel(grid, border_style="yellow", title="SECURITY WARNING (TIMED)"))
                # Spawn auto-expire thread
                timer_thread = threading.Thread(
                    target=self._expire_clipboard,
                    args=(content, self.timeout),
                    daemon=True,
                )
                timer_thread.start()
            else:
                grid.add_row("[dim]Tip: Run 'clipguard purge' or use --timeout 30 to auto-wipe after 30s.[/dim]")
                console.print(Panel(grid, border_style="yellow", title="SECURITY WARNING"))

            # Save to storage with safety flag
            self.storage.add_entry(
                content=content,
                is_secret=True,
                secret_type=matches_summary,
                masked_preview=result.masked_content,
                store_redacted=self.store_redacted or self.auto_purge,
            )
        else:
            # Safe content
            self.storage.add_entry(
                content=content,
                is_secret=False,
                secret_type=None,
                masked_preview=content,
                store_redacted=False,
            )
            preview = content.strip().replace("\n", " ")
            if len(preview) > 60:
                preview = preview[:57] + "..."
            console.print(f"[dim]{time.strftime('%H:%M:%S')}[/dim] [green]✓ Captured:[/green] [white]{preview}[/white]")
