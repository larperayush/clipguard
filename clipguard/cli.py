"""
CLI interface for ClipGuard.
"""

import click
import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clipguard import __version__
from clipguard.detector import detect_secrets
from clipguard.monitor import ClipboardWatcher
from clipguard.storage import StorageManager

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="clipguard")
def main():
    """🛡️ ClipGuard - Smart Developer Clipboard & Secret Catcher."""
    pass


@main.command()
@click.option("--auto-purge", is_flag=True, help="Automatically wipe clipboard when a secret is detected.")
@click.option("--store-redacted", is_flag=True, help="Store redacted content in history rather than raw secrets.")
@click.option("--interval", default=0.5, type=float, help="Clipboard polling interval in seconds.")
def watch(auto_purge: bool, store_redacted: bool, interval: float):
    """Start the live clipboard watcher and secret detection daemon."""
    storage = StorageManager()
    watcher = ClipboardWatcher(
        storage=storage,
        auto_purge=auto_purge,
        store_redacted=store_redacted,
        poll_interval=interval,
    )
    watcher.start()


@main.command(name="list")
@click.option("-n", "--limit", default=15, help="Number of items to display.")
@click.option("--pinned", is_flag=True, help="Show only pinned snippets.")
def list_history(limit: int, pinned: bool):
    """List recent clipboard history."""
    storage = StorageManager()
    items = storage.get_history(limit=limit, pinned_only=pinned)

    if not items:
        console.print("[dim]No clipboard history found.[/dim]")
        return

    table = Table(title="📋 Clipboard History", border_style="cyan", show_lines=True)
    table.add_column("ID", style="bold cyan", width=4)
    table.add_column("Status", width=12)
    table.add_column("Preview", style="white")
    table.add_column("Chars", justify="right", width=6)
    table.add_column("Time", style="dim", width=16)

    for item in items:
        status_badges = []
        if item.is_pinned:
            badge = "📌 PINNED"
            if item.pin_label:
                badge += f" ({item.pin_label})"
            status_badges.append(f"[bold yellow]{badge}[/bold yellow]")
        if item.is_secret:
            status_badges.append(f"[bold red]⚠️ {item.secret_type or 'SECRET'}[/bold red]")
        if not status_badges:
            status_badges.append("[green]✓ Safe[/green]")

        table.add_row(
            str(item.id),
            "\n".join(status_badges),
            item.preview,
            str(item.char_count),
            item.last_used_at.split(".")[0],
        )

    console.print(table)


@main.command()
@click.argument("query")
@click.option("-n", "--limit", default=10, help="Maximum search results.")
def search(query: str, limit: int):
    """Search clipboard history by text or snippet tag."""
    storage = StorageManager()
    items = storage.search_history(query, limit=limit)

    if not items:
        console.print(f"[dim]No matching entries for '[bold]{query}[/bold]'.[/dim]")
        return

    table = Table(title=f"🔍 Results for '{query}'", border_style="magenta", show_lines=True)
    table.add_column("ID", style="bold cyan", width=4)
    table.add_column("Preview", style="white")
    table.add_column("Type", width=15)

    for item in items:
        status = "[red]SECRET[/red]" if item.is_secret else "[green]SAFE[/green]"
        if item.is_pinned:
            status += " (📌)"
        table.add_row(str(item.id), item.preview, status)

    console.print(table)


@main.command()
@click.argument("item_id", type=int)
def copy(item_id: int):
    """Copy an item from history back into your active clipboard."""
    storage = StorageManager()
    item = storage.get_item(item_id)
    if not item:
        console.print(f"[bold red]Error:[/bold red] Item #{item_id} not found.")
        return

    pyperclip.copy(item.content)
    console.print(f"[green]✓ Copied item #{item_id} to clipboard.[/green]")


@main.command()
@click.argument("item_id", type=int)
@click.option("--label", default=None, help="Optional label or description for this pin.")
def pin(item_id: int, label: str):
    """Pin an entry to prevent it from ever being purged."""
    storage = StorageManager()
    if storage.pin_entry(item_id, label):
        console.print(f"[green]✓ Pinned item #{item_id}[/green]" + (f" with label: '{label}'" if label else ""))
    else:
        console.print(f"[bold red]Error:[/bold red] Item #{item_id} not found.")


@main.command()
@click.argument("item_id", type=int)
def unpin(item_id: int):
    """Unpin an entry."""
    storage = StorageManager()
    if storage.unpin_entry(item_id):
        console.print(f"[yellow]✓ Unpinned item #{item_id}.[/yellow]")
    else:
        console.print(f"[bold red]Error:[/bold red] Item #{item_id} not found.")


@main.command()
@click.argument("text", required=False)
def scan(text: str):
    """Inspect current clipboard or provided text for leaked credentials."""
    target_text = text if text is not None else pyperclip.paste()

    if not target_text or not target_text.strip():
        console.print("[dim]Target is empty. Nothing to scan.[/dim]")
        return

    result = detect_secrets(target_text)

    if result.is_secret:
        table = Table(title="⚠️ Secrets Detected", border_style="red")
        table.add_column("Type", style="bold red")
        table.add_column("Confidence", style="yellow")
        table.add_column("Position", style="dim")

        for m in result.matches:
            table.add_row(m.secret_type, m.confidence, f"{m.start}..{m.end}")

        console.print(table)
        console.print(f"\n[bold]Masked Output:[/bold]\n[cyan]{result.masked_content}[/cyan]")
    else:
        console.print("[bold green]✓ Clean![/bold green] No sensitive credentials or high-entropy secrets detected.")


@main.command()
def purge():
    """Purge all unpinned secrets from history and wipe the active clipboard if sensitive."""
    storage = StorageManager()
    purged_count = storage.purge_secrets()

    # Also check active clipboard
    current_clip = pyperclip.paste()
    res = detect_secrets(current_clip)
    clip_purged = False
    if res.is_secret:
        pyperclip.copy("")
        clip_purged = True

    console.print(
        Panel.fit(
            f"[bold green]Purge Complete![/bold green]\n"
            f"• Database records purged: [bold red]{purged_count}[/bold red]\n"
            f"• Current clipboard wiped: [{'bold red]YES[/bold red]' if clip_purged else '[dim]Not needed (safe)[/dim]'}",
            border_style="green",
        )
    )


@main.command()
@click.option("--all", "wipe_all", is_flag=True, help="Clear everything including pinned snippets.")
def clear(wipe_all: bool):
    """Clear clipboard history."""
    storage = StorageManager()
    count = storage.clear_all(keep_pinned=not wipe_all)
    console.print(f"[yellow]Cleared {count} items from history{' (retained pinned items)' if not wipe_all else ''}.[/yellow]")


if __name__ == "__main__":
    main()
