"""
Clipboard monitoring daemon.
Watches system clipboard for new entries, triggers security inspections, and handles safety actions.
"""

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
    ):
        self.storage = storage or StorageManager()
        self.auto_purge = auto_purge
        self.store_redacted = store_redacted
        self.poll_interval = poll_interval
        self._last_content: Optional[str] = None

    def start(self):
        console.print(
            Panel.fit(
                "[bold cyan]🛡️ ClipGuard Watcher Active[/bold cyan]\n"
                f"[dim]Auto-Purge Secrets:[/dim] [{'bold red]ENABLED[/bold red]' if self.auto_purge else '[yellow]DISABLED[/yellow]'}\n"
                f"[dim]Store Redacted Only:[/dim] [{'bold green]YES[/bold green]' if self.store_redacted else '[yellow]NO[/yellow]'}\n"
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

    def process_clip(self, content: str):
        if not content or not content.strip():
            return

        result = detect_secrets(content)

        if result.is_secret:
            matches_summary = ", ".join({m.secret_type for m in result.matches})

            # Print warning box
            grid = Table.grid(expand=True)
            grid.add_column(justify="left")
            grid.add_row(f"[bold red]⚠️ SECRET LEAK PREVENTED![/bold red]")
            grid.add_row(f"[yellow]Detected:[/yellow] [bold white]{matches_summary}[/bold white]")
            grid.add_row(f"[dim]Masked Preview:[/dim] [cyan]{result.masked_content[:80]}[/cyan]...")

            if self.auto_purge:
                # Wipe clipboard immediately
                pyperclip.copy("")
                grid.add_row("[bold red]Action:[/bold red] [strike]Clipboard purged immediately![/strike]")
                console.print(Panel(grid, border_style="red", title="SECURITY ALERT"))
            else:
                grid.add_row("[dim]Tip: Run 'clipguard purge' or use --auto-purge to wipe secrets automatically.[/dim]")
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
