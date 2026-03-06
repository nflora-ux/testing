import os
from pathlib import Path

APPNAME = "Tocket"
VERSION = "Tocket-Core - v4.2.0.2 (c) Mar 2026    https://github.com/neveerlabs/Tocket.git"

DB_DIR = Path.home() / f".{APPNAME.lower()}"
DB_FILE = DB_DIR / "tocket.db"