#!/usr/bin/env python3
"""
VENOM Installer v7.0
====================
Installs VENOM and its modules/ package as a system command.

Linux / macOS  →  ~/.local/bin/venom  (or /usr/local/bin with --sudo)
Windows        →  %APPDATA%\\venom\\venom.bat  (added to user PATH)

Usage:
    python3 install.py              Install
    python3 install.py --sudo       Install system-wide (Linux/macOS)
    python3 install.py --update     Update in-place
    python3 install.py --uninstall  Remove completely
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

# ── Colour helpers ────────────────────────────────────────────────────────────

def _supports_colour():
    if platform.system() == "Windows":
        return os.environ.get("TERM") or os.environ.get("WT_SESSION")
    return sys.stdout.isatty()

_COL = _supports_colour()

def green(s):  return f"\033[92m{s}\033[0m" if _COL else s
def red(s):    return f"\033[91m{s}\033[0m" if _COL else s
def yellow(s): return f"\033[93m{s}\033[0m" if _COL else s
def bold(s):   return f"\033[1m{s}\033[0m"  if _COL else s
def dim(s):    return f"\033[2m{s}\033[0m"  if _COL else s
def cyan(s):   return f"\033[96m{s}\033[0m" if _COL else s

def ok(msg):   print(f"  {green('[+]')} {msg}")
def err(msg):  print(f"  {red('[-]')} {msg}")
def warn(msg): print(f"  {yellow('[!]')} {msg}")
def info(msg): print(f"  {dim(' * ')} {msg}")
def step(msg): print(f"\n{bold(cyan('  >>> ' + msg))}")


BANNER = r"""
 __      ________ _   _  ____  __  __ 
 \ \    / /  ____| \ | |/ __ \|  \/  |
  \ \  / /| |__  |  \| | |  | | \  / |
   \ \/ / |  __| | . ` | |  | | |\/| |
    \  /  | |____| |\  | |__| | |  | |
     \/   |______|_| \_|\____/|_|  |_|

  Installer v7.0
"""

REQUIRED = ["aiohttp", "click", "rich"]

# ── Python version ────────────────────────────────────────────────────────────

def check_python():
    ver = sys.version_info
    info(f"Python {ver.major}.{ver.minor}.{ver.micro}")
    if ver < (3, 8):
        err(f"Python 3.8+ required — you have {ver.major}.{ver.minor}")
        print("  Get it at https://python.org/downloads/")
        sys.exit(1)
    ok("Python version OK")

# ── Dependencies ──────────────────────────────────────────────────────────────

def install_deps():
    step("Installing dependencies")
    missing = []
    for pkg in REQUIRED:
        try:
            __import__(pkg)
            ok(f"{pkg} already installed")
        except ImportError:
            missing.append(pkg)

    for pkg in missing:
        info(f"pip install {pkg} ...")
        base_cmd = [sys.executable, "-m", "pip", "install", pkg, "--quiet"]
        # --break-system-packages required on Debian/Ubuntu 3.11+
        cmds = (
            base_cmd + ["--break-system-packages"],
            base_cmd,
        ) if platform.system() != "Windows" else (base_cmd,)

        installed = False
        for cmd in cmds:
            try:
                subprocess.check_call(cmd, stderr=subprocess.DEVNULL)
                ok(f"{pkg} installed")
                installed = True
                break
            except subprocess.CalledProcessError:
                continue

        if not installed:
            err(f"Could not install {pkg}")
            print(f"\n  Fix manually:  pip install {pkg}\n")
            sys.exit(1)

# ── Locate source files ───────────────────────────────────────────────────────

def find_source() -> Path:
    """
    Return the directory containing venom.py + modules/.
    Checks: same dir as install.py, then cwd.
    """
    candidates = [Path(__file__).parent, Path.cwd()]
    for d in candidates:
        if (d / "venom.py").exists() and (d / "modules").is_dir():
            return d.resolve()

    # Fallback: venom.py only (old single-file layout — warn but continue)
    for d in candidates:
        if (d / "venom.py").exists():
            warn("modules/ directory not found — installing single-file layout")
            warn("For the full modular install, clone the complete repo")
            return d.resolve()

    err("Cannot find venom.py")
    print("\n  Run install.py from inside the cloned repo directory.\n")
    sys.exit(1)

# ── Copy source tree ──────────────────────────────────────────────────────────

def copy_source(src_dir: Path, dest_dir: Path):
    """Copy venom.py and modules/ to dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    # venom.py
    shutil.copy2(src_dir / "venom.py", dest_dir / "venom.py")
    ok(f"venom.py -> {dest_dir / 'venom.py'}")

    # modules/
    src_modules  = src_dir / "modules"
    dest_modules = dest_dir / "modules"
    if src_modules.is_dir():
        if dest_modules.exists():
            shutil.rmtree(dest_modules)
        shutil.copytree(
            src_modules, dest_modules,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        ok(f"modules/ -> {dest_modules}")

# ── Linux / macOS install ─────────────────────────────────────────────────────

UNIX_WRAPPER = """\
#!/bin/sh
exec {python} {script} "$@"
"""

def install_unix(src_dir: Path, sudo: bool):
    step("Installing for Linux / macOS")

    if sudo or (hasattr(os, "geteuid") and os.geteuid() == 0):
        data_dir   = Path("/opt/venom")
        bin_dir    = Path("/usr/local/bin")
    else:
        data_dir   = Path.home() / ".local" / "share" / "venom"
        bin_dir    = Path.home() / ".local" / "bin"

    copy_source(src_dir, data_dir)

    # Wrapper script
    bin_dir.mkdir(parents=True, exist_ok=True)
    wrapper = bin_dir / "venom"
    wrapper.write_text(UNIX_WRAPPER.format(
        python=sys.executable,
        script=str(data_dir / "venom.py"),
    ))
    wrapper.chmod(0o755)
    ok(f"wrapper -> {wrapper}")

    # PATH check
    path_dirs = [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep)]
    if bin_dir not in path_dirs:
        warn(f"{bin_dir} is not on your PATH")
        shell = Path(os.environ.get("SHELL", "/bin/sh")).name
        rc    = "~/.zshrc" if shell == "zsh" else "~/.bashrc"
        print(f"\n  Add to {rc} and restart your terminal:\n")
        print(f'    export PATH="$HOME/.local/bin:$PATH"\n')
    else:
        ok(f"{bin_dir} already on PATH")

    _done_unix()

def _done_unix():
    print(f"\n  {green(bold('Installation complete!'))}")
    print(f"\n  Run:  {bold('venom --help')}\n")

# ── Windows install ───────────────────────────────────────────────────────────

WIN_WRAPPER = """\
@echo off
"{python}" "{script}" %*
"""

def _win_user_path() -> str:
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(k, "Path")
        winreg.CloseKey(k)
        return val
    except Exception:
        return ""

def _set_win_user_path(new_path: str) -> bool:
    try:
        import winreg, ctypes
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
        winreg.CloseKey(k)
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x1A, 0, "Environment", 2, 5000, None)
        return True
    except Exception as e:
        warn(f"Registry write failed: {e}")
        return False

def install_windows(src_dir: Path):
    step("Installing for Windows")

    appdata  = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    data_dir = appdata / "venom"

    copy_source(src_dir, data_dir)

    wrapper = data_dir / "venom.bat"
    wrapper.write_text(WIN_WRAPPER.format(
        python=sys.executable,
        script=str(data_dir / "venom.py"),
    ))
    ok(f"wrapper -> {wrapper}")

    # PATH
    user_path = _win_user_path()
    parts = [p.strip() for p in user_path.split(";") if p.strip()]
    if str(data_dir) not in parts:
        new_path = ";".join(parts + [str(data_dir)])
        if _set_win_user_path(new_path):
            ok(f"Added {data_dir} to user PATH")
            warn("Open a new terminal for PATH to take effect")
        else:
            warn("Could not update PATH automatically")
            print(f"\n  Add manually:  {data_dir}")
            print("  Control Panel -> System -> Advanced -> Environment Variables\n")
    else:
        ok(f"{data_dir} already on PATH")

    print(f"\n  {green(bold('Installation complete!'))}")
    print(f"\n  Open a new terminal, then run:  {bold('venom --help')}\n")

# ── Update ────────────────────────────────────────────────────────────────────

def update(src_dir: Path):
    step("Updating VENOM")
    system = platform.system()

    if system == "Windows":
        appdata  = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        dest_dir = appdata / "venom"
    else:
        dest_dir = Path.home() / ".local" / "share" / "venom"
        if not dest_dir.exists():
            dest_dir = Path("/opt/venom")

    if not dest_dir.exists():
        err("VENOM is not installed. Run install.py without --update first.")
        sys.exit(1)

    copy_source(src_dir, dest_dir)
    print(f"\n  {green(bold('Update complete!'))}\n")

# ── Uninstall ─────────────────────────────────────────────────────────────────

def uninstall():
    step("Uninstalling VENOM")
    system = platform.system()

    if system == "Windows":
        appdata  = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        data_dir = appdata / "venom"
        _rm(data_dir)
        # Remove from PATH
        user_path = _win_user_path()
        parts = [p for p in user_path.split(";") if p.strip() and str(data_dir) not in p]
        _set_win_user_path(";".join(parts))
        ok("Removed from user PATH")
    else:
        for data_dir in [
            Path.home() / ".local" / "share" / "venom",
            Path("/opt/venom"),
        ]:
            _rm(data_dir)
        for wrapper in [
            Path.home() / ".local" / "bin" / "venom",
            Path("/usr/local/bin/venom"),
        ]:
            if wrapper.exists():
                wrapper.unlink()
                ok(f"Removed {wrapper}")

    print(f"\n  {green(bold('Uninstall complete.'))}\n")

def _rm(path: Path):
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
        ok(f"Removed {path}")
    else:
        info(f"Not found — skipping: {path}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print(bold(green(BANNER)))

    parser = argparse.ArgumentParser(
        description="VENOM installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python3 install.py              Install VENOM
          python3 install.py --sudo       Install to /usr/local/bin (Linux/macOS)
          python3 install.py --update     Update in-place
          python3 install.py --uninstall  Remove completely
        """)
    )
    parser.add_argument("--sudo",      action="store_true",
                        help="Install to /usr/local/bin (Linux/macOS, requires root)")
    parser.add_argument("--update",    action="store_true",
                        help="Update installed files to current version")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove VENOM from the system")
    args = parser.parse_args()

    system = platform.system()
    info(f"Platform: {system} {platform.machine()}")
    check_python()

    if args.uninstall:
        uninstall()
        return

    src_dir = find_source()
    info(f"Source: {src_dir}")

    install_deps()

    if args.update:
        update(src_dir)
        return

    if system == "Windows":
        install_windows(src_dir)
    elif system in ("Linux", "Darwin"):
        install_unix(src_dir, sudo=args.sudo)
    else:
        warn(f"Unknown platform: {system} — attempting Unix-style install")
        install_unix(src_dir, sudo=False)


if __name__ == "__main__":
    main()
