#!/usr/bin/env python3
import sys
import os
import traceback
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse
import inquirer
from inquirer.themes import GreenPassion
from rich.table import Table
from rich import box
from rich.prompt import Confirm, Prompt

from .constants import VERSION, APPNAME
from .db import ConfigDB
from .utils import (
    clear_screen, print_header, read_binary_file,
    display_error, display_success, display_warning, console
)
from .github_api import GitHubClient

ASCII_ART = r"""
TTTTTTTTTT  OOOOO  CCCCC K   K EEEEE TTTTTTTTTT
    TT     O     O C     K  K  E         TT
    TT     O     O C     KKK   EEEE      TT
    TT     O     O C     K  K  E         TT
    TT      OOOOO  CCCCC K   K EEEEE     TT
"""

def ensure_db() -> ConfigDB:
    return ConfigDB()

def mask_token(tok: str) -> str:
    if not tok:
        return ""
    if len(tok) <= 8:
        return tok[:2] + "..." + tok[-2:]
    return tok[:4] + "..." + tok[-4:]

def _parse_github_url(url_or_repo: str) -> Tuple[Optional[str], Optional[str]]:
    if not url_or_repo:
        return None, None
    s = url_or_repo.strip()
    if s.startswith("http://") or s.startswith("https://"):
        try:
            p = urlparse(s)
            parts = p.path.strip("/").split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]
            if len(parts) == 1:
                return parts[0], None
        except Exception:
            return None, None
    if "/" in s:
        parts = s.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    return None, s

def get_repo_default_branch(gh: GitHubClient, owner: str, repo: str) -> Optional[str]:
    try:
        if hasattr(gh, "get_default_branch"):
            b = gh.get_default_branch(owner, repo)
            if b:
                return b
    except Exception:
        pass
    try:
        if hasattr(gh, "get_repo"):
            data = gh.get_repo(owner, repo)
            if data and data.get("default_branch"):
                return data.get("default_branch")
    except Exception:
        pass
    for b in ("main", "master"):
        try:
            r = gh.session.get(f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{b}", timeout=10)
            if r.status_code == 200:
                return b
        except Exception:
            continue
    return None

def login_flow(db: ConfigDB) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    pwd_salt = db.get_kv("pwd_salt")
    password: Optional[str] = None

    if pwd_salt:
        questions = [
            inquirer.Password('pwd', message="Masukkan password lokal"),
        ]
        attempts = 0
        while attempts < 3:
            answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
            if answers is None:
                display_warning("Batal input password.")
                return None, None, None
            pwd = answers['pwd']
            if db.verify_password(pwd):
                password = pwd
                break
            else:
                display_error("Password yang dimasukkan salah!")
                attempts += 1
        if attempts >= 3 and password is None:
            display_error("Mencapai batas percobaan.")
            sys.exit(1)
    else:
        display_warning("Tidak ada password lokal — lanjutkan tanpa password atau buat password lewat Pengaturan nanti.")

    token: Optional[str] = None
    label: Optional[str] = None

    if db.get_kv("tok_cipher"):
        if password is None:
            display_warning("Token terenkripsi ditemukan, tetapi tidak ada password. Masukkan password terlebih dahulu.")
            questions = [
                inquirer.Password('pwd', message="Masukkan password lokal"),
            ]
            answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
            if answers is None:
                return None, None, None
            pwd = answers['pwd']
            if not db.verify_password(pwd):
                display_error("Password salah!")
                return None, None, None
            password = pwd
        token = db.load_token_decrypted(password)
        if token is None:
            display_error("Gagal dekripsi token — kemungkinan password berbeda. Kamu bisa reset token di Pengaturan.")
        else:
            label = db.get_kv("tok_label")
            display_success(f"Token tersimpan ditemukan untuk label: [cyan]{label or '(no label)'}[/cyan]")
    else:
        while True:
            questions = [
                inquirer.Text('token', message="Masukkan token classic GitHub (kosongkan untuk lanjut tanpa token)"),
            ]
            answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
            if answers is None:
                token = None
                break
            t = answers['token'].strip()
            if not t:
                token = None
                break
            try:
                gh = GitHubClient(t)
                info = gh.validate_token()
            except Exception as e:
                display_error(f"Gagal memvalidasi token: {e}")
                continue

            if info:
                display_success(f"Token valid. Username: [cyan]{info['username']}[/cyan]. Scopes: [magenta]{info['scopes']}[/magenta]")
                questions = [
                    inquirer.Text('label', message="Nama / catatan untuk token (opsional)"),
                ]
                label_ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
                label = label_ans['label'].strip() if label_ans else ""

                if not db.get_kv("pwd_salt"):
                    questions = [
                        inquirer.Confirm('create_pwd', message="Mau membuat password untuk mengenkripsi token?", default=False),
                    ]
                    pwd_ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
                    if pwd_ans and pwd_ans['create_pwd']:
                        questions = [
                            inquirer.Password('pwd', message="Buat password baru"),
                        ]
                        pwd2_ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
                        if pwd2_ans:
                            pwd = pwd2_ans['pwd']
                            db.set_password(pwd)
                            db.store_token_encrypted(t, pwd)
                            if label:
                                db.set_kv("tok_label", label)
                            db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                            display_success("Token tersimpan dan terenkripsi.")
                            token = t
                            break
                    else:
                        questions = [
                            inquirer.Confirm('session', message="Simpan token hanya untuk sesi saat ini (tidak disimpan permanen)?", default=False),
                        ]
                        sess_ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
                        if sess_ans and sess_ans['session']:
                            token = t
                            break
                        else:
                            continue
                else:
                    questions = [
                        inquirer.Password('pwd', message="Masukkan password lokal untuk mengenkripsi token"),
                    ]
                    pwd_ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
                    if pwd_ans and pwd_ans['pwd'] and db.verify_password(pwd_ans['pwd']):
                        db.store_token_encrypted(t, pwd_ans['pwd'])
                        if label:
                            db.set_kv("tok_label", label)
                        db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                        display_success("Token tersimpan dan terenkripsi.")
                        token = t
                        break
                    else:
                        display_error("Password tidak cocok. Token tidak disimpan.")
                        token = t
                        break
            else:
                display_error("Token tidak valid. Coba lagi.")
                continue
    return password, token, label

def main_menu_loop(db: ConfigDB, gh_client: Optional[GitHubClient], username: str, password: Optional[str]):
    while True:
        clear_screen()
        print_header(ASCII_ART, VERSION, username or "anonymous")
        questions = [
            inquirer.List('action',
                          message=f"{username}@Tocket $ Pilih aksi",
                          choices=[
                              ('Buat Repositori', '1'),
                              ('Lihat Repositori', '2'),
                              ('Setup Repositori', '3'),
                              ('Hapus Repositori', '4'),
                              ('Pengaturan', '5'),
                              ('Keluar', '6'),
                          ],
                          carousel=True)
        ]
        try:
            answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
            if answers is None:
                continue
            choice = answers['action']
        except KeyboardInterrupt:
            print("\n")
            continue

        if choice == '1':
            create_repo_flow(db, gh_client, username, password)
        elif choice == '2':
            list_repos_flow(db, gh_client)
        elif choice == '3':
            setup_repo_flow(db, gh_client, username, password)
        elif choice == '4':
            delete_repo_flow(db, gh_client, username)
        elif choice == '5':
            settings_flow(db, gh_client, password)
        elif choice == '6':
            display_success("Sampai jumpa!")
            break

def create_repo_flow(db: ConfigDB, gh: Optional[GitHubClient], username: str, password: Optional[str]):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk membuat repositori. Tambahkan token di Pengaturan.")
            input("\nTekan Enter untuk kembali...")
            return

        questions = [
            inquirer.Text('name', message="Nama repositori", validate=lambda _, x: x.strip() != ""),
            inquirer.Text('desc', message="Deskripsi (opsional)"),
            inquirer.Confirm('private', message="Buat repositori private?", default=False),
            inquirer.Confirm('readme', message="Tambahkan README?", default=True),
            inquirer.Confirm('gitignore', message="Tambahkan .gitignore?", default=False),
            inquirer.Confirm('license', message="Tambahkan License?", default=False),
        ]
        answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
        if answers is None:
            return

        name = answers['name'].strip()
        desc = answers['desc'].strip()
        private = answers['private']
        auto_init = answers['readme']

        gi_template = None
        if answers['gitignore']:
            try:
                templates = gh.get_gitignore_templates()
                table = Table(title="Template .gitignore", box=box.ROUNDED)
                table.add_column("No", justify="right", style="cyan")
                table.add_column("Nama", style="white")
                for i, t in enumerate(templates[:60], 1):
                    table.add_row(str(i), t)
                console.print(table)
                choices = [(t, t) for t in templates[:60]]
                q = inquirer.List('gi', message="Pilih template .gitignore", choices=choices, carousel=True)
                gi_ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
                if gi_ans:
                    gi_template = gi_ans['gi']
            except Exception as e:
                display_error(f"Gagal mengambil template .gitignore: {e}")

        lic_template = None
        if answers['license']:
            try:
                licenses = gh.get_license_templates()
                table = Table(title="Template License", box=box.ROUNDED)
                table.add_column("No", justify="right", style="cyan")
                table.add_column("Key", style="white")
                table.add_column("Nama", style="white")
                for i, l in enumerate(licenses[:30], 1):
                    table.add_row(str(i), l.get('key'), l.get('name'))
                console.print(table)
                choices = [(f"{l.get('key')} - {l.get('name')}", l.get('key')) for l in licenses[:30]]
                q = inquirer.List('lic', message="Pilih template License", choices=choices, carousel=True)
                lic_ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
                if lic_ans:
                    lic_template = lic_ans['lic']
            except Exception as e:
                display_error(f"Gagal mengambil template License: {e}")

        repo = gh.create_repo(name=name, description=desc, private=private,
                              auto_init=auto_init, gitignore_template=gi_template,
                              license_template=lic_template)
        db.add_history("create_repo", repo.get("full_name"))
        display_success(f"Repositori dibuat: {repo.get('html_url')}")
    except Exception as e:
        display_error(f"Gagal membuat repositori: {e}")
        if "token" in str(e).lower():
            display_warning("Pastikan token memiliki scope 'repo'.")
    finally:
        input("\nTekan Enter untuk kembali ke menu...")

def list_repos_flow(db: ConfigDB, gh: Optional[GitHubClient]):
    try:
        gh_local = gh
        repos = None

        if gh_local and getattr(gh_local, "token", None):
            try:
                repos = gh_local.list_repos()
            except Exception as e:
                display_error(f"Gagal list repos dengan token saat ini: {e}")
                if "401" in str(e) or "unauthorized" in str(e).lower() or "invalid" in str(e).lower():
                    if Confirm.ask("Token invalid/expired. Mau masukkan token baru sekarang?"):
                        new_tok = Prompt.ask("Masukkan token classic GitHub", default="")
                        if not new_tok:
                            display_warning("Batal memasukkan token baru.")
                            return
                        tmp = GitHubClient(new_tok.strip())
                        try:
                            info = tmp.validate_token()
                        except Exception as e2:
                            display_error(f"Token baru tidak valid: {e2}")
                            return
                        label = Prompt.ask("Nama / catatan untuk token (opsional)", default="")
                        if db.get_kv("pwd_salt"):
                            pwd = Prompt.ask("Masukkan password lokal untuk mengenkripsi token", password=True) if Confirm.ask("Enkripsi token dengan password?") else None
                            if pwd and db.verify_password(pwd):
                                db.store_token_encrypted(new_tok.strip(), pwd)
                                db.set_kv("tok_label", label or "")
                                db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                                display_success("Token tersimpan dan terenkripsi.")
                        else:
                            if Confirm.ask("Mau membuat password untuk mengenkripsi token sekarang? (disarankan)"):
                                pwd = Prompt.ask("Buat password baru", password=True)
                                if pwd:
                                    db.set_password(pwd)
                                    db.store_token_encrypted(new_tok.strip(), pwd)
                                    db.set_kv("tok_label", label or "")
                                    db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                                    display_success("Token tersimpan dan terenkripsi.")
                        try:
                            repos = tmp.list_repos()
                            gh_local = tmp
                        except Exception as e2:
                            display_error(f"Gagal mengambil repo dengan token baru: {e2}")
                            return
                else:
                    display_error(f"Gagal mengambil repo: {e}")
                    return

        if repos is None:
            display_warning("Tidak ada token autentikasi. Kamu dapat memasukkan token untuk melihat semua repos (termasuk private), atau melihat public repos dari username.")
            if Confirm.ask("Ingin memasukkan token sekarang?"):
                t = Prompt.ask("Masukkan token classic GitHub", default="")
                if not t:
                    display_warning("Dibatalkan.")
                    return
                tmp = GitHubClient(t.strip())
                try:
                    info = tmp.validate_token()
                except Exception as e:
                    display_error(f"Token tidak valid: {e}")
                    return
                label = Prompt.ask("Nama / catatan untuk token (opsional)", default="")
                if db.get_kv("pwd_salt"):
                    pwd = Prompt.ask("Masukkan password lokal untuk mengenkripsi token", password=True) if Confirm.ask("Enkripsi token dengan password?") else None
                    if pwd and db.verify_password(pwd):
                        db.store_token_encrypted(t.strip(), pwd)
                        db.set_kv("tok_label", label or "")
                        db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                        display_success("Token tersimpan dan terenkripsi.")
                else:
                    if Confirm.ask("Mau membuat password untuk mengenkripsi token sekarang? (disarankan)"):
                        pwd = Prompt.ask("Buat password baru", password=True)
                        if pwd:
                            db.set_password(pwd)
                            db.store_token_encrypted(t.strip(), pwd)
                            db.set_kv("tok_label", label or "")
                            db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                            display_success("Token tersimpan dan terenkripsi.")
                gh_local = tmp
                try:
                    repos = gh_local.list_repos()
                except Exception as e:
                    display_error(f"Gagal mengambil repo dengan token: {e}")
                    return
            else:
                user = Prompt.ask("Masukkan username GitHub untuk melihat public repos (kosong batal)", default="")
                if not user:
                    return
                try:
                    gh_public = GitHubClient()
                    repos = gh_public.list_user_public_repos(user)
                except Exception as e:
                    display_error(f"Gagal mengambil public repos untuk {user}: {e}")
                    return

        if not repos:
            display_warning("Tidak ada repositori untuk ditampilkan. Coba buat repo baru atau periksa token/username lo.")
            return

        table = Table(title="Repositori", box=box.SIMPLE)
        table.add_column("Repositori", style="cyan", no_wrap=True)
        table.add_column("Visibilitas", justify="center")
        table.add_column("Branch", justify="center")

        for r in repos:
            name = r.get("name") or r.get("full_name") or str(r.get("html_url") or "")
            visibility = "private" if r.get("private") else "public"
            branch = r.get("default_branch")
            if not branch:
                try:
                    if gh_local and hasattr(gh_local, "get_default_branch"):
                        branch = gh_local.get_default_branch(r.get("owner", {}).get("login") or "", r.get("name") or "")
                    elif gh_local and hasattr(gh_local, "get_repo"):
                        repo_meta = gh_local.get_repo(r.get("owner", {}).get("login") or "", r.get("name") or "")
                        branch = repo_meta.get("default_branch")
                except Exception:
                    branch = "-"
            table.add_row(name, visibility, branch or "-")

        console.print(table)
    except Exception as e:
        display_error(f"Gagal mengambil daftar repositori: {e}")
        traceback.print_exc()
    finally:
        input("\nTekan Enter untuk kembali ke menu...")

def delete_repo_flow(db: ConfigDB, gh: Optional[GitHubClient], username: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token dengan scope repo untuk menghapus repositori.")
            input("\nTekan Enter...")
            return

        questions = [
            inquirer.Text('name', message=f"Nama repositori (https://github.com/{username}/[nama])"),
            inquirer.Confirm('confirm', message="Yakin ingin menghapus repositori ini? Tindakan ini tidak bisa dibatalkan.", default=False),
        ]
        answers = inquirer.prompt(questions, raise_keyboard_interrupt=True)
        if answers is None or not answers['confirm']:
            display_warning("Dibatalkan.")
            return

        name = answers['name'].strip()
        gh.delete_repo(username, name)
        db.add_history("delete_repo", f"{username}/{name}")
        display_success("Repositori berhasil dihapus.")
    except Exception as e:
        display_error(f"Gagal menghapus repo: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def setup_repo_flow(db: ConfigDB, gh: Optional[GitHubClient], username: str, password: Optional[str]):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk mengelola repositori. Tambahkan token di Pengaturan.")
            input("\nTekan Enter...")
            return

        questions = [
            inquirer.Text('repo', message=f"Nama repositori (https://github.com/{username}/[nama])"),
        ]
        ans = inquirer.prompt(questions, raise_keyboard_interrupt=True)
        if ans is None:
            return
        repo_name = ans['repo'].strip()
        if not repo_name:
            return

        try:
            found = False
            repos = gh.list_repos()
            found = any(r.get("name") == repo_name for r in repos)
            if not found:
                display_error("Repositori tidak ditemukan di akun Anda.")
                return
        except Exception as e:
            display_error(f"Gagal memeriksa repositori: {e}")
            return

        while True:
            console.print(f"\n[bold cyan]Setup Repositori: {username}/{repo_name}[/bold cyan]")
            menu_choices = [
                ('Upload file', '1'),
                ('Hapus file', '2'),
                ('Rename file/folder', '3'),
                ('List file', '4'),
                ('Ubah visibilitas', '5'),
                ('Ubah .gitignore', '6'),
                ('Ubah License', '7'),
                ('Hapus folder', '8'),
                ('Kembali', '0'),
            ]
            q = inquirer.List('opt', message="Pilih opsi", choices=menu_choices, carousel=True)
            opt_ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
            if opt_ans is None:
                return
            opt = opt_ans['opt']
            if opt == '1':
                upload_file_flow(db, gh, username, repo_name)
            elif opt == '2':
                delete_file_flow(db, gh, username, repo_name)
            elif opt == '3':
                rename_file_or_folder_flow(db, gh, username, repo_name)
            elif opt == '4':
                list_files_flow(db, gh, username, repo_name)
            elif opt == '5':
                change_visibility_flow(db, gh, username, repo_name)
            elif opt == '6':
                change_gitignore_flow(db, gh, username, repo_name)
            elif opt == '7':
                change_license_flow(db, gh, username, repo_name)
            elif opt == '8':
                delete_folder_flow(db, gh, username, repo_name)
            elif opt == '0':
                break
    except Exception as e:
        display_error(f"Gagal di setup repo: {e}")
    finally:
        input("\nTekan Enter untuk kembali ke menu...")

def display_directory(path: Path):
    files = list(path.iterdir())
    table = Table(title=f"Isi folder: {path}", box=box.ROUNDED)
    table.add_column("No", justify="right", style="cyan")
    table.add_column("Nama", style="white")
    table.add_column("Tipe", justify="center")
    table.add_column("Ukuran", justify="right")
    for idx, p in enumerate(files, start=1):
        nama = p.name
        tipe = "DIR" if p.is_dir() else "FILE"
        ukuran = ""
        if p.is_file():
            size = p.stat().st_size
            if size < 1024:
                ukuran = f"{size} B"
            elif size < 1024**2:
                ukuran = f"{size/1024:.1f} KB"
            else:
                ukuran = f"{size/1024**2:.1f} MB"
        else:
            ukuran = "-"
        table.add_row(str(idx), nama, tipe, ukuran)
    console.print(table)
    console.print("[dim]0: .. (ke folder parent)[/dim]")
    console.print("[dim]all: Upload semua file di folder ini (tanpa subfolder)[/dim]")
    console.print("[dim]subfolder: Upload seluruh folder ini beserta subfolder (rekursif)[/dim]")
    console.print("[dim]q: batal[/dim]")

def upload_file_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk meng-upload file.")
            return

        start_path = Prompt.ask("Mulai path file (kosong = current directory)", default=".")
        current = Path(start_path).expanduser().resolve()

        while True:
            display_directory(current)
            sel = Prompt.ask("Pilih nomor / ketik filename (atau 'q' untuk batal)", default="")
            if sel.lower() == 'q':
                return
            if sel.lower() == 'all':
                repo_path = Prompt.ask("Simpan path di repo (kosong = root, atau folder/ diakhiri '/' untuk folder)", default="")
                branch = get_repo_default_branch(gh, owner, repo) or Prompt.ask("Masukkan branch target", default="main")
                files_to_upload = [p for p in current.iterdir() if p.is_file()]
                if not files_to_upload:
                    display_warning("Tidak ada file di folder ini.")
                    continue
                success = 0
                for p in files_to_upload:
                    target = (repo_path.strip() + p.name) if repo_path.strip() else p.name
                    try:
                        content = read_binary_file(str(p))
                        gh.create_or_update_file(owner, repo, target, content, message=f"Tocket: upload {target}", branch=branch)
                        success += 1
                        display_success(f"Upload {p.name} sukses")
                    except Exception as e:
                        display_error(f"Gagal upload {p.name}: {e}")
                        if not Confirm.ask("Lanjutkan upload file berikutnya?"):
                            break
                display_success(f"Upload selesai: {success} dari {len(files_to_upload)} file berhasil.")
                input("\nTekan Enter untuk kembali...")
                return
            if sel.lower() == 'subfolder':
                # Gunakan nama folder saat ini sebagai base path di repo
                base_folder = current.name
                if not base_folder:
                    display_error("Tidak dapat menentukan nama folder.")
                    return
                repo_path = base_folder + "/"
                branch = get_repo_default_branch(gh, owner, repo) or Prompt.ask("Masukkan branch target", default="main")
                all_files = []
                for root, dirs, files in os.walk(current):
                    root_path = Path(root)
                    for file in files:
                        full_path = root_path / file
                        rel_path = full_path.relative_to(current)
                        all_files.append((full_path, rel_path))
                if not all_files:
                    display_warning("Tidak ada file di folder ini.")
                    continue
                success = 0
                for full_path, rel_path in all_files:
                    target = repo_path + rel_path.as_posix()
                    try:
                        content = read_binary_file(str(full_path))
                        gh.create_or_update_file(owner, repo, target, content, message=f"Tocket: upload {target}", branch=branch)
                        success += 1
                        display_success(f"Upload {rel_path} sukses")
                    except Exception as e:
                        display_error(f"Gagal upload {rel_path}: {e}")
                        if not Confirm.ask("Lanjutkan upload file berikutnya?"):
                            break
                display_success(f"Upload selesai: {success} dari {len(all_files)} file berhasil.")
                input("\nTekan Enter untuk kembali...")
                return
            if sel == "":
                fname = Prompt.ask("Masukkan nama file di folder ini (atau full path)")
                if not fname:
                    continue
                path = Path(fname)
                if not path.is_absolute():
                    path = current / path
                if not path.exists() or not path.is_file():
                    display_error("File tidak ditemukan.")
                    continue
                if path.stat().st_size > 100 * 1024 * 1024:
                    display_error("File terlalu besar untuk di-upload via GitHub Contents API (>100MB).")
                    continue
                repo_path = Prompt.ask("Simpan path di repo (kosong = root, atau folder/ diakhiri '/' untuk folder)", default="")
                target_path = (repo_path.strip() + path.name) if repo_path.strip() else path.name
                try:
                    branch = get_repo_default_branch(gh, owner, repo) or Prompt.ask("Masukkan branch target", default="main")
                    content = read_binary_file(str(path))
                    gh.create_or_update_file(owner, repo, target_path, content, message=f"Tocket: upload {target_path}", branch=branch)
                    db.add_history("upload_file", f"{owner}/{repo}/{target_path}")
                    display_success(f"Upload sukses: {target_path}")
                    return
                except Exception as e:
                    display_error(f"Gagal upload: {e}")
                    continue
            else:
                try:
                    idx = int(sel)
                    if idx == 0:
                        if current.parent == current:
                            display_warning("Sudah root.")
                        else:
                            current = current.parent
                    else:
                        files = list(current.iterdir())
                        if 1 <= idx <= len(files):
                            chosen = files[idx - 1]
                            if chosen.is_dir():
                                current = chosen
                            else:
                                path = chosen
                                if path.stat().st_size > 100 * 1024 * 1024:
                                    display_error("File terlalu besar.")
                                    return
                                repo_path = Prompt.ask("Simpan path di repo (kosong = root)", default="")
                                target_path = (repo_path.strip() + path.name) if repo_path.strip() else path.name
                                branch = get_repo_default_branch(gh, owner, repo) or Prompt.ask("Masukkan branch target", default="main")
                                content = read_binary_file(str(path))
                                gh.create_or_update_file(owner, repo, target_path, content, message=f"Tocket: upload {target_path}", branch=branch)
                                db.add_history("upload_file", f"{owner}/{repo}/{target_path}")
                                display_success(f"Upload sukses: {target_path}")
                                return
                        else:
                            display_error("Nomor tidak valid.")
                except ValueError:
                    display_error("Input tidak dikenali.")
    except Exception as e:
        display_error(f"Error upload flow: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def delete_file_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk menghapus file.")
            return
        fname = Prompt.ask("Masukkan nama file (path relatif di repo) untuk dihapus")
        if not fname:
            return
        if not Confirm.ask(f"Yakin ingin menghapus file {fname}?"):
            display_warning("Dibatalkan.")
            return
        branch = get_repo_default_branch(gh, owner, repo) or "main"
        gh.delete_file(owner, repo, fname, message=f"Tocket: delete {fname}", branch=branch)
        db.add_history("delete_file", f"{owner}/{repo}/{fname}")
        display_success("File dihapus.")
    except FileNotFoundError as e:
        display_error(str(e))
    except Exception as e:
        display_error(f"Gagal menghapus file: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def list_files_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        client = gh or GitHubClient()
        branch = get_repo_default_branch(client, owner, repo) or "main"
        tree = client.list_repo_tree(owner, repo, branch=branch)
        table = Table(title=f"Files in {owner}/{repo} (branch={branch})", box=box.MINIMAL)
        table.add_column("Path")
        table.add_column("Type")
        table.add_column("Size")
        for t in tree:
            table.add_row(t.get("path", ""), t.get("type", ""), str(t.get("size", "-")))
        console.print(table)
    except Exception as e:
        display_error(f"Gagal mengambil file list: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def change_visibility_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk mengubah visibilitas.")
            return
        q = inquirer.List('vis', message="Pilih visibilitas", choices=['public', 'private'], carousel=True)
        ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
        if ans is None:
            return
        vis = ans['vis']
        payload = {"private": (vis == "private")}
        gh.patch_repo(owner, repo, payload)
        db.add_history("change_visibility", f"{owner}/{repo} -> {vis}")
        display_success("Visibilitas berhasil diubah.")
    except Exception as e:
        display_error(f"Gagal mengubah visibilitas: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def rename_file_or_folder_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk rename file/folder.")
            return
        src = Prompt.ask("Masukkan nama file/folder yang ingin di-rename (path relatif di repo)")
        if not src:
            return
        dest = Prompt.ask("Masukkan nama baru untuk file/folder yang ingin di-rename (path relatif di repo)")
        if not dest:
            return
        branch = get_repo_default_branch(gh, owner, repo) or "main"
        tree = gh.list_repo_tree(owner, repo, branch=branch)
        src = src.rstrip("/")
        dest = dest.rstrip("/")
        to_move = [item for item in tree if item.get("path") == src or item.get("path", "").startswith(src + "/")]
        if not to_move:
            display_error(f"{src} not found in {owner}/{repo}")
            return
        for item in to_move:
            if item.get("type") != "blob":
                continue
            old_path = item.get("path")
            if old_path == src:
                new_path = dest
            else:
                suffix = old_path[len(src) + 1:]
                new_path = dest + "/" + suffix if suffix else dest
            contents = gh.get_contents(owner, repo, old_path, ref=branch)
            if not contents:
                continue
            if contents.get("content"):
                import base64
                data = base64.b64decode(contents.get("content"))
            else:
                dl = gh.session.get(contents.get("download_url"))
                data = dl.content
            gh.create_or_update_file(owner, repo, new_path, data, message=f"Tocket: move {old_path} -> {new_path}", branch=branch)
            gh.delete_file(owner, repo, old_path, message=f"Tocket: delete {old_path} (moved)", branch=branch)
            db.add_history("rename_move", f"{owner}/{repo}/{old_path} -> {new_path}")
        display_success("Rename/move selesai.")
    except Exception as e:
        display_error(f"Gagal rename/move: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def change_gitignore_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk mengubah .gitignore.")
            return
        templates = gh.get_gitignore_templates()
        table = Table(title="Template .gitignore", box=box.ROUNDED)
        table.add_column("No", justify="right", style="cyan")
        table.add_column("Nama", style="white")
        for i, t in enumerate(templates[:100], 1):
            table.add_row(str(i), t)
        console.print(table)
        choices = [(t, t) for t in templates[:100]]
        q = inquirer.List('tmpl', message="Pilih template .gitignore (atau pilih custom)", choices=choices + [('(custom)', 'custom')], carousel=True)
        ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
        if ans is None:
            return
        chosen = ans['tmpl']
        chosen_content = None
        if chosen == 'custom':
            chosen_content = Prompt.ask("Masukkan isi .gitignore (enter untuk batal)", default="")
            if not chosen_content:
                display_warning("Tidak ada isi.")
                return
        else:
            r = gh.session.get(f"https://api.github.com/gitignore/templates/{chosen}")
            if r.status_code == 200:
                chosen_content = r.json().get("source")
        if not chosen_content:
            display_error("Gagal mengambil template.")
            return
        branch = get_repo_default_branch(gh, owner, repo) or "main"
        gh.create_or_update_file(owner, repo, ".gitignore", chosen_content.encode("utf-8"), message="Tocket: update .gitignore", branch=branch)
        db.add_history("update_gitignore", f"{owner}/{repo}")
        display_success(".gitignore diupdate.")
    except Exception as e:
        display_error(f"Gagal update .gitignore: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def change_license_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk mengubah License.")
            return
        licenses = gh.get_license_templates()
        table = Table(title="Template License", box=box.ROUNDED)
        table.add_column("No", justify="right", style="cyan")
        table.add_column("Key", style="white")
        table.add_column("Nama", style="white")
        for i, l in enumerate(licenses[:60], 1):
            table.add_row(str(i), l.get('key'), l.get('name'))
        console.print(table)
        choices = [(f"{l.get('key')} - {l.get('name')}", l.get('key')) for l in licenses[:60]]
        q = inquirer.List('lic', message="Pilih template License", choices=choices + [('(custom)', 'custom')], carousel=True)
        ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
        if ans is None:
            return
        chosen = ans['lic']
        content = None
        if chosen == 'custom':
            content = Prompt.ask("Masukkan isi License (enter untuk batal)", default="")
            if not content:
                display_warning("Tidak ada isi.")
                return
        else:
            r = gh.session.get(f"https://api.github.com/licenses/{chosen}")
            if r.status_code == 200:
                content = r.json().get("body")
        if not content:
            display_error("Gagal mengambil template.")
            return
        branch = get_repo_default_branch(gh, owner, repo) or "main"
        gh.create_or_update_file(owner, repo, "LICENSE", content.encode("utf-8"), message="Tocket: update LICENSE", branch=branch)
        db.add_history("update_license", f"{owner}/{repo}")
        display_success("LICENSE diupdate.")
    except Exception as e:
        display_error(f"Gagal update LICENSE: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def delete_folder_flow(db: ConfigDB, gh: Optional[GitHubClient], owner: str, repo: str):
    try:
        if gh is None or gh.token is None:
            display_error("Butuh token untuk menghapus folder.")
            return
        folder = Prompt.ask("Masukkan nama folder yang ingin dihapus (path relatif di repo)")
        if not folder:
            return
        if not Confirm.ask(f"Yakin ingin menghapus folder {folder} dan seluruh isinya?"):
            display_warning("Dibatalkan.")
            return
        branch = get_repo_default_branch(gh, owner, repo) or "main"
        tree = gh.list_repo_tree(owner, repo, branch=branch)
        to_delete = [t for t in tree if t.get("path") == folder or t.get("path", "").startswith(folder.rstrip("/") + "/")]
        for item in sorted(to_delete, key=lambda x: x.get("path"), reverse=True):
            if item.get("type") != "blob":
                continue
            path = item.get("path")
            gh.delete_file(owner, repo, path, message=f"Tocket: delete {path}", branch=branch)
            db.add_history("delete_file", f"{owner}/{repo}/{path}")
        display_success("Folder dan isinya dihapus.")
    except Exception as e:
        display_error(f"Gagal menghapus folder: {e}")
    finally:
        input("\nTekan Enter untuk kembali...")

def settings_flow(db: ConfigDB, gh: Optional[GitHubClient], password: Optional[str]):
    try:
        while True:
            console.print("\n[bold cyan]Pengaturan[/bold cyan]")
            menu_choices = [
                ('Tampilkan Token classic', '1'),
                ('Ubah token classic', '2'),
                ('Hapus token classic', '3'),
                ('Ubah password', '4'),
                ('Hapus password', '5'),
                ('Buat password', '7'),
                ('Kembali', '6'),
            ]
            q = inquirer.List('opt', message="Pilih opsi", choices=menu_choices, carousel=True)
            ans = inquirer.prompt([q], raise_keyboard_interrupt=True)
            if ans is None:
                return
            opt = ans['opt']

            if opt == '1':
                cipher = db.get_kv("tok_cipher")
                if not cipher:
                    display_warning("Tidak ada token tersimpan.")
                else:
                    label = db.get_kv("tok_label") or "(tidak ada label)"
                    scopes_db = db.get_kv("tok_scopes") or ""
                    if not password:
                        pwd_q = inquirer.Password('pwd', message="Masukkan password untuk dekripsi token")
                        pwd_ans = inquirer.prompt([pwd_q], raise_keyboard_interrupt=True)
                        if not pwd_ans or not db.verify_password(pwd_ans['pwd']):
                            display_error("Password salah.")
                            continue
                        token = db.load_token_decrypted(pwd_ans['pwd'])
                    else:
                        token = db.load_token_decrypted(password)
                    if token:
                        masked = mask_token(token)
                        console.print(f"Label: {label}")
                        console.print(f"Token: {masked}")
                        console.print(f"Scopes: {scopes_db}")
                        if Confirm.ask("Tampilkan token penuh?"):
                            console.print(f"Token: {token}")
                    else:
                        display_error("Gagal mendekripsi token.")
            elif opt == '2':
                t = Prompt.ask("Masukkan token classic GitHub (kosong untuk batal)", default="")
                if not t:
                    continue
                tmp_client = GitHubClient(t)
                try:
                    info = tmp_client.validate_token()
                except Exception as e:
                    display_error(f"Token tidak valid: {e}")
                    continue
                label = Prompt.ask("Nama / catatan token (opsional)", default="")
                if not password:
                    pwd_q = inquirer.Password('pwd', message="Masukkan password lokal untuk mengenkripsi token")
                    pwd_ans = inquirer.prompt([pwd_q], raise_keyboard_interrupt=True)
                    if not pwd_ans or not db.verify_password(pwd_ans['pwd']):
                        display_error("Password salah. Token tidak disimpan.")
                        continue
                    db.store_token_encrypted(t, pwd_ans['pwd'])
                else:
                    db.store_token_encrypted(t, password)
                if label:
                    db.set_kv("tok_label", label)
                db.set_kv("tok_scopes", ",".join(info.get("scopes") or []))
                display_success("Token tersimpan.")
            elif opt == '3':
                if Confirm.ask("Yakin ingin menghapus token classic dari storage?"):
                    db.clear_token()
                    db.delete_kv("tok_label")
                    db.delete_kv("tok_scopes")
                    display_success("Token dihapus dari DB.")
            elif opt == '4':
                if not db.get_kv("pwd_salt"):
                    display_warning("Belum ada password. Gunakan Buat password.")
                    continue
                current_q = inquirer.Password('current', message="Masukkan password saat ini")
                current_ans = inquirer.prompt([current_q], raise_keyboard_interrupt=True)
                if not current_ans or not db.verify_password(current_ans['current']):
                    display_error("Password salah.")
                    continue
                new_q = inquirer.Password('new', message="Masukkan password baru")
                new_ans = inquirer.prompt([new_q], raise_keyboard_interrupt=True)
                if not new_ans or not new_ans['new']:
                    display_warning("Dibatalkan.")
                    continue
                token_val = db.load_token_decrypted(current_ans['current'])
                db.set_password(new_ans['new'])
                if token_val:
                    db.store_token_encrypted(token_val, new_ans['new'])
                display_success("Password diubah dan token dire-enkripsi.")
            elif opt == '5':
                if Confirm.ask("Yakin ingin menghapus password lokal? Ini juga akan menghapus token terenkripsi."):
                    db.clear_password()
                    db.clear_token()
                    db.delete_kv("tok_label")
                    db.delete_kv("tok_scopes")
                    display_success("Password dan token dihapus dari storage.")
            elif opt == '7':
                if db.get_kv("pwd_salt"):
                    display_warning("Password sudah ada. Gunakan ubah password.")
                    continue
                new_q = inquirer.Password('new', message="Buat password baru")
                new_ans = inquirer.prompt([new_q], raise_keyboard_interrupt=True)
                if not new_ans or not new_ans['new']:
                    display_warning("Dibatalkan.")
                    continue
                db.set_password(new_ans['new'])
                display_success("Password berhasil dibuat.")
            elif opt == '6':
                break
    except KeyboardInterrupt:
        display_warning("Dibatalkan.")
    finally:
        input("\nTekan Enter untuk kembali ke menu...")

def main():
    db = ensure_db()
    pwd, token, label = login_flow(db)
    gh_client: Optional[GitHubClient] = None
    username = "anonymous"
    if token:
        try:
            gh_client = GitHubClient(token)
            info = gh_client.validate_token()
            if info:
                username = info.get("username") or username
            else:
                display_warning("Token tidak valid saat login awal.")
                gh_client = None
        except Exception as e:
            display_error(f"Gagal validasi token saat startup: {e}")
            gh_client = None
    else:
        display_warning("Beberapa fitur butuh token. Lanjutkan tanpa token terbatas.")

    try:
        main_menu_loop(db, gh_client, username, pwd)
    finally:
        db.close()

if __name__ == "__main__":
    main()