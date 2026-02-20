#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import json
import os
import re
import socket
import signal
import shlex
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path
from urllib import error, request
import tomllib
import config as config_module

from colorama import Fore

from config import (
    ANTHROPIC_API_KEY,
    API_ENDPOINT,
    APP_NAME,
    APP_VERSION,
    GEMINI_API_KEY,
    OLLAMA_MODEL,
    OPENAI_API_KEY,
    PYPI_PACKAGE,
)
from utils.ui import clear, cyber


# ═══════════════════════════════════════════════════════════════
#  :: Utilities
#  Utility functions such as ApiKEY verifier and signal handler
# ═══════════════════════════════════════════════════════════════
def checkAPI():
    if API_ENDPOINT == "NOT_SET":
        print(Fore.RED + "\nNo custom API set. Please configure in source code at API_ENPOINT")
        sys.exit(0)


def _read_key(name, config_value):
    env_key = os.getenv(name, "").strip()
    if env_key:
        os.environ[name] = env_key
        return env_key
    cfg_key = str(config_value or "").strip()
    if cfg_key and cfg_key != "NOT_SET":
        os.environ[name] = cfg_key
        return cfg_key
    return ""


def _persist_key_to_config(name, key):
    cfg_path = Path(config_module.__file__).resolve()
    try:
        raw = cfg_path.read_text(encoding="utf-8")
    except OSError:
        return False

    serialized = json.dumps(str(key))
    line = f"{name} = {serialized}"
    pattern = rf"^{re.escape(name)}\s*=.*$"
    if re.search(pattern, raw, flags=re.MULTILINE):
        updated = re.sub(pattern, line, raw, flags=re.MULTILINE)
    else:
        updated = raw.rstrip() + f"\n{line}\n"

    if updated == raw:
        return True

    try:
        cfg_path.write_text(updated, encoding="utf-8")
        return True
    except OSError:
        return False


def _ensure_provider_key(name, label, config_value):
    key = _read_key(name, config_value)
    if key:
        return key

    os.system("clear")
    cyber(f"{label} key not found! :: Please insert it below", color=Fore.RED)
    print("\nYour API key will be stored locally in config.py\n")
    key = input("#key > ").strip()
    if not key:
        print(Fore.RED + "\nNo key provided. Aborting.")
        sys.exit(1)

    os.environ[name] = key
    if _persist_key_to_config(name, key):
        print(Fore.GREEN + f"\n✔ {label} API key saved in config.py.")
    else:
        print(Fore.YELLOW + f"\n[!] Could not persist {label} key in config.py, using this session only.")
    time.sleep(1)
    return key


def checkOpenAIKey():
    return _ensure_provider_key("OPENAI_API_KEY", "OpenAI", OPENAI_API_KEY)


def checkAnthropicKey():
    return _ensure_provider_key("ANTHROPIC_API_KEY", "Anthropic", ANTHROPIC_API_KEY)


def checkGeminiKey():
    return _ensure_provider_key("GEMINI_API_KEY", "Gemini", GEMINI_API_KEY)


def ctrl_c_handler(signum, frame):
    raise KeyboardInterrupt


def register_signal_handler():
    signal.signal(signal.SIGINT, ctrl_c_handler)


def graceful_exit():
    cyber("EVA OFFLINE :: SESSION IS SAVED", color=Fore.RED)
    print(Fore.YELLOW + "🜂  E x i t i n g  E V A ...")
    time.sleep(2.5)
    clear()
    sys.exit(0)


def _split_version(value):
    clean = str(value).strip().lower().lstrip("v")
    parts = []
    for part in clean.split("."):
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits or 0))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _is_newer(latest, current):
    return _split_version(latest) > _split_version(current)


def get_current_version():
    try:
        return metadata.version(PYPI_PACKAGE)
    except metadata.PackageNotFoundError:
        pyproject = Path("pyproject.toml")
        if pyproject.exists():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                version = data.get("project", {}).get("version")
                if version:
                    return version
            except (tomllib.TOMLDecodeError, OSError):
                pass
    return APP_VERSION


def fetch_latest_pypi_version():
    url = f"https://pypi.org/pypi/{PYPI_PACKAGE}/json"
    req = request.Request(url, headers={"Accept": "application/json", "User-Agent": "eva-update-check"})
    try:
        with request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("info", {}).get("version")
    except (error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def checkupdts():
    try:
        socket.create_connection(("pypi.org", 443), timeout=2)
    except OSError:
        return

    current = get_current_version()
    latest = fetch_latest_pypi_version()
    if not latest:
        return
    if _is_newer(latest, current):
        print("\n" + Fore.CYAN + "=" * 40)
        print(Fore.CYAN + f"🐱 Update available: {current} → {latest}")
        print(Fore.GREEN + "Run: eva -u to update to the latest version")
        print("=" * 40 + Fore.CYAN + "\n")


def run_self_update():
    print(Fore.CYAN + f"\nChecking updates for {APP_NAME}...\n")
    updated = False

    pip_result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", PYPI_PACKAGE],
        text=True
    )
    if pip_result.returncode == 0:
        updated = True

    if Path(".git").exists() and command_exists("git"):
        branch = "main"
        branch_detect = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True
        )
        if branch_detect.returncode == 0 and branch_detect.stdout.strip():
            branch = branch_detect.stdout.strip()

        pull_result = subprocess.run(["git", "pull", "--tags", "origin", branch], text=True)
        if pull_result.returncode == 0:
            updated = True

    if updated:
        print(Fore.GREEN + "\n✔ Update process finished. Restart EVA to use the latest version.")
        return 0

    print(Fore.RED + "\n[!] Could not auto-update EVA in this environment.")
    print(Fore.YELLOW + f"Try manually: {sys.executable} -m pip install --upgrade {PYPI_PACKAGE}")
    return 1


# ================= STARTUP OF EVA here =================
def command_exists(cmd):
    return subprocess.call(
        ["which", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0


def ollama_running():
    try:
        subprocess.check_output(['ollama', 'list'], stderr=subprocess.STDOUT, text=True)
        return True
    except subprocess.CalledProcessError as e:
        if "server not responding" in e.output.lower():
            return False
        return False


def start_ollama():
    clear()
    print("\n\n\n")
    print(Fore.YELLOW + "🜂 OLLAMA NOT RUNNING :: Starting for you...\n\n")

    with open(os.devnull, 'w') as DEVNULL:
        subprocess.Popen(
            ['ollama', 'serve'],
            stdout=DEVNULL,
            stderr=DEVNULL,
            stdin=DEVNULL,
            close_fds=True,
            start_new_session=True
        )

    time.sleep(3)


def model_exists():
    r = subprocess.run(
        ["ollama", "list"],
        capture_output=True,
        text=True
    )
    return OLLAMA_MODEL in r.stdout


def open_in_default_editor(path):
    target = Path(path).expanduser().resolve()
    if not target.exists():
        return False, f"File not found: {target}"

    editor = os.environ.get("EDITOR", "").strip()
    try:
        if editor:
            editor_args = shlex.split(editor)
            terminal_editors = {"vi", "vim", "nvim", "nano", "micro", "emacs", "hx", "kak"}
            base = Path(editor_args[0]).name if editor_args else ""
            if base in terminal_editors:
                if sys.stdin.isatty() and sys.stdout.isatty():
                    proc = subprocess.run([*editor_args, str(target)])
                    if proc.returncode == 0:
                        return True, f"Edited with $EDITOR: {target}"
                    return False, f"$EDITOR exited with status {proc.returncode}"
            else:
                subprocess.Popen([*editor_args, str(target)])
                return True, f"Opened with $EDITOR: {target}"
    except OSError:
        pass

    try:
        if sys.platform.startswith("darwin"):
            proc = subprocess.run(
                ["open", str(target)],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if proc.returncode == 0:
                return True, f"Opened config file: {target}"
            err = (proc.stderr or proc.stdout or "").strip()
            return False, f"Failed to open file: {err or 'open returned non-zero status'}"
        if os.name == "nt":
            os.startfile(str(target))
            return True, f"Opened config file: {target}"
        proc = subprocess.run(
            ["xdg-open", str(target)],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode == 0:
            return True, f"Opened config file: {target}"
        err = (proc.stderr or proc.stdout or "").strip()
        return False, f"Failed to open file: {err or 'xdg-open returned non-zero status'}"
    except OSError as exc:
        return False, f"Failed to open file: {exc}"
    except subprocess.TimeoutExpired:
        return False, "Failed to open file: opener timed out"
