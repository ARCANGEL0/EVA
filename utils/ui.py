#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import os
import re
import sys
import termios
import tty
import itertools
import threading
import time
from colorama import Fore, Style, init

init(autoreset=True)


def clear():
    os.system("clear")


# ════════════════════
#  :: UI FUNCTIONS
# ════════════════════

_spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_spinner_text = " L o a d i n g "
_spinner_delay = 0.10
_spinner_running = False
_spinner_thread = None


def _spinner_animate():
    for i, frame in enumerate(itertools.cycle(_spinner_frames)):
        if not _spinner_running:
            break
        dot_count = (i // 3) % 4 + 1
        dots = "." * dot_count
        spaces = " " * (4 - dot_count)
        sys.stdout.write(f"\r  {frame}  {_spinner_text}{dots}{spaces}")
        sys.stdout.flush()
        time.sleep(_spinner_delay)


def spinner_start():
    global _spinner_running, _spinner_thread
    if _spinner_running:
        return
    _spinner_running = True
    sys.stdout.write(f"\n\n")
    _spinner_thread = threading.Thread(target=_spinner_animate)
    _spinner_thread.daemon = True
    _spinner_thread.start()


def spinner_stop():
    global _spinner_running
    _spinner_running = False
    if _spinner_thread:
        _spinner_thread.join()
    sys.stdout.write("\r" + " " * (len(_spinner_text) + 4) + "\r")
    sys.stdout.flush()


def cyber(msg="", width=50, color=Fore.GREEN):
    """
    Stylized output in a centered scifi box.
    :param msg: message
    :param width: width
    :param color: Ccolor
    """
    width = int(width)
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")

    def visible_len(text):
        return len(ansi_re.sub("", text))

    lines = str(msg).splitlines() if msg else []
    longest = max((visible_len(line) for line in lines), default=0)
    width = max(width, longest + 4)

    print(color + "╔" + "═" * width + "╗")
    if lines:
        for line in lines:
            line_len = visible_len(line)
            content_len = line_len + 2
            padding = max(0, width - content_len)
            left_pad = padding // 2
            right_pad = padding - left_pad
            print(color + "║" + " " * left_pad + " " + line + " " + " " * right_pad + "║")
    print(color + "╚" + "═" * width + "╝")
    print(Style.RESET_ALL)



def banner(version=None):
    clear()
    print(Style.BRIGHT + Fore.CYAN + rf"""
╔═════════════════════════════════════════════╗
║                                             ║
║  ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░    ║
║  ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░   ║
║  ░▒▓█▓▒░       ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░   ║
║  ░▒▓██████▓▒░  ░▒▓█▓▒▒▓█▓▒░░▒▓████████▓▒░   ║
║  ░▒▓█▓▒░        ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░   ║
║  ░▒▓█▓▒░        ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░   ║
║  ░▒▓████████▓▒░  ░▒▓██▓▒░  ░▒▓█▓▒░░▒▓█▓▒░   ║
║                       Exploit Vector Agent  ║
║                                             ║
║ ᴍᴀᴅᴇ ʙʏ: 𝝺𝗿𝗰𝗮𝗻𝗴𝗲𝗹𝗼                          ║
╚═════════════════════════════════════════════╝
{Style.BRIGHT} {Fore.MAGENTA} version: {version} {Style.RESET_ALL} """)


# ╔═════════░░░═════════╗
# ░░░   Query input   ░░░
# ╚═════════░░░═════════╝
def raw_input(prompt=""):
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf = ""
    try:
        tty.setcbreak(fd)
        print(prompt, end="", flush=True)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                print()
                return buf
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    print("\b \b", end="", flush=True)
            elif ch == "\x03":
                raise KeyboardInterrupt
            else:
                buf += ch
                print(ch, end="", flush=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ╔═════════░░░═════════╗
# ░░░ Control utilies ░░░
# ╚═════════░░░═════════╝

def menu(title, options):
    idx = 0
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            os.system("clear")
            cyber(title)
            for i, opt in enumerate(options):
                prefix = "→ " if i == idx else "  "
                print(prefix + opt)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                sys.stdin.read(1)
                arrow = sys.stdin.read(1)
                if arrow == "A":
                    idx = (idx - 1) % len(options)
                elif arrow == "B":
                    idx = (idx + 1) % len(options)
            elif ch in ("\n", "\r"):
                return idx
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
def get_sessions(title, options, version=None):
    idx = 0
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            banner(version)
            print("\n")
            cyber(title)
            for i, opt in enumerate(options):
                prefix = "→ " if i == idx else "  "
                print(prefix + opt)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                sys.stdin.read(1)
                arrow = sys.stdin.read(1)
                if arrow == "A":
                    idx = (idx - 1) % len(options)
                elif arrow == "B":
                    idx = (idx + 1) % len(options)
            elif ch in ("\n", "\r"):
                return idx
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
