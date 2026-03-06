import os
import base64
from pathlib import Path
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich.style import Style

console = Console()

def clear_screen():
    """Membersihkan layar..."""
    os.system("cls" if os.name == "nt" else "clear")

def ensure_app_dir(path: Path):
    """Membuat direktori aplikasi jika belum ada."""
    path.mkdir(parents=True, exist_ok=True)

def read_binary_file(path: str) -> bytes:
    """Baca file sebagai bytes."""
    with open(path, "rb") as f:
        return f.read()

def to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def from_base64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def print_header(ascii_text: str, about_text: str, username: str):
    """Tampilkan header dengan ASCII art dan panel."""
    txt = Text(ascii_text + "\n\n", style=Style(color="green"))
    txt.append(about_text + "\n", style=Style(color="white"))
    panel = Panel(txt, title=f"[cyan]{username}[/cyan]  [green]tocket[/green]")
    console.print(panel)

def display_error(message: str):
    console.print(f"[bold red]⚠️ ERROR: {message}[/bold red]")

def display_success(message: str):
    console.print(f"[bold green]✅ {message}[/bold green]")

def display_warning(message: str):
    console.print(f"[bold yellow]⚠️ {message}[/bold yellow]")