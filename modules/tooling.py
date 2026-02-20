#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import os
import re
import shlex
import shutil

OPERATORS = {"&&", "||", "|", ";"}
SUDO_VALUE_OPTS = {"-p", "-u", "-g", "-h", "-C", "-T", "-t", "-r"}
PROBE_COMMANDS = {"which", "command", "type", "whereis"}
SKIP_EXEC_TOKENS = {
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case",
    "esac", "function", "{", "}", "(", ")",
}
SHELL_BUILTINS = {
    "alias", "bg", "bind", "break", "builtin", "cd", "command", "compgen",
    "complete", "continue", "declare", "dirs", "disown", "echo", "enable",
    "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash",
    "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile",
    "popd", "printf", "pushd", "pwd", "read", "readonly", "return", "set",
    "shift", "shopt", "source", "suspend", "test", "times", "trap", "true",
    "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait", "[",
}
TOOL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./+-]+$")
COMPLEX_SHELL_RE = re.compile(r"\$\(|`|<\(|>\(|\n")
PATH_FLAG_VALUES = {
    "-w", "--wordlist", "-W",
    "-r", "--request", "--config", "--script", "--scripts", "-iL",
}
FORCE_SUDO_TOOLS = {"nmap", "masscan", "arp-scan", "tcpdump"}


def _is_valid_tool_token(token):
    if not token:
        return False
    if token in SKIP_EXEC_TOKENS:
        return False
    if token in OPERATORS:
        return False
    if token.startswith("$"):
        return False
    return TOOL_TOKEN_RE.match(token) is not None


def _has_complex_shell_syntax(cmd):
    return bool(COMPLEX_SHELL_RE.search(cmd or ""))


def _looks_like_local_path(token):
    if not token:
        return False
    if "://" in token:
        return False
    if token.startswith(("/", "./", "../", "~/")):
        return True
    return False


def _normalize_path_token(token):
    if token.startswith("~"):
        return os.path.expanduser(token)
    return token


def _tokenize_shell(cmd):
    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return (cmd or "").split()


def _split_segments(tokens):
    segments = []
    operators = []
    current = []
    for tok in tokens:
        if tok in OPERATORS:
            segments.append(current)
            operators.append(tok)
            current = []
        else:
            current.append(tok)
    segments.append(current)
    return segments, operators


def _join_segments(segments, operators):
    out = []
    for idx, seg in enumerate(segments):
        if seg:
            out.append(shlex.join(seg))
        if idx < len(operators):
            out.append(operators[idx])
    return " ".join(out).strip()


def _primary_tool_from_tokens(parts):
    if not parts:
        return ""

    idx = 0
    skip = {"env", "time", "command", "nohup", "stdbuf"}

    while idx < len(parts):
        tok = parts[idx]

        if tok == "sudo":
            idx += 1
            while idx < len(parts) and parts[idx].startswith("-"):
                opt = parts[idx]
                idx += 1
                if opt in SUDO_VALUE_OPTS and idx < len(parts):
                    idx += 1
            continue

        if tok in skip:
            idx += 1
            continue

        if "=" in tok and not tok.startswith("/"):
            key = tok.split("=", 1)[0]
            if key and key.replace("_", "").isalnum():
                idx += 1
                continue

        if tok.startswith("-"):
            idx += 1
            continue

        if _is_valid_tool_token(tok):
            return tok
        idx += 1

    return ""


def extract_primary_tool(cmd):
    if not cmd or not isinstance(cmd, str):
        return ""
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return ""
    segments, _ = _split_segments(tokens)
    for seg in segments:
        tool = _primary_tool_from_tokens(seg)
        if tool:
            return tool
    return ""


def tool_exists(tool):
    if not tool:
        return True
    if tool in SHELL_BUILTINS:
        return True
    return shutil.which(tool) is not None


def install_one_liner(tool):
    if not tool or not _is_valid_tool_token(tool):
        return ""
    if shutil.which("apt-get"):
        return f"sudo apt-get update -y && sudo apt-get install -y {tool}"
    if shutil.which("dnf"):
        return f"sudo dnf install -y {tool}"
    if shutil.which("yum"):
        return f"sudo yum install -y {tool}"
    if shutil.which("pacman"):
        return f"sudo pacman -Sy --noconfirm {tool}"
    if shutil.which("zypper"):
        return f"sudo zypper --non-interactive install {tool}"
    if shutil.which("brew"):
        return f"brew install {tool}"
    return ""


def extract_tools(cmd):
    if not cmd or not isinstance(cmd, str):
        return []
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return []
    segments, _ = _split_segments(tokens)
    tools = []
    seen = set()
    for seg in segments:
        if not seg:
            continue
        tool = _primary_tool_from_tokens(seg)
        if not tool:
            continue
        if tool in PROBE_COMMANDS:
            for arg in seg[1:]:
                if arg.startswith("-"):
                    continue
                if not _is_valid_tool_token(arg):
                    continue
                if arg in SHELL_BUILTINS:
                    continue
                if arg not in seen:
                    seen.add(arg)
                    tools.append(arg)
            continue
        if tool in SHELL_BUILTINS:
            continue
        if tool not in seen:
            seen.add(tool)
            tools.append(tool)
    return tools


def normalize_sudo_invocations(cmd):
    if not cmd:
        return cmd
    pattern = re.compile(r"(?<![\w-])sudo(?![\w-])(?!\s+-S\b)")
    return pattern.sub("sudo -S -p ''", cmd)


def count_sudo_invocations(cmd):
    if not cmd:
        return 0
    return len(re.findall(r"(?<![\w-])sudo(?![\w-])", cmd))


def strip_output_flags(cmd):
    if not cmd or not isinstance(cmd, str):
        return cmd
    if _has_complex_shell_syntax(cmd):
        return cmd
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return cmd

    segments, operators = _split_segments(tokens)
    out_flags = {"-o", "--output", "-output", "-oN", "-oX", "-oG", "-oA"}
    modified = False
    cleaned_segments = []
    for seg in segments:
        rebuilt = []
        i = 0
        while i < len(seg):
            t = seg[i]
            lower = t.lower()
            if t in out_flags:
                modified = True
                i += 2
                continue
            if lower.startswith("--output=") or lower.startswith("-output="):
                modified = True
                i += 1
                continue
            if re.match(r"^-o[anxg]$", lower):
                modified = True
                i += 2
                continue
            rebuilt.append(t)
            i += 1
        cleaned_segments.append(rebuilt)

    if not modified:
        return cmd
    cleaned = _join_segments(cleaned_segments, operators)
    return cleaned.strip()


def _default_wordlist_candidates():
    return [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]


def _find_existing_wordlist():
    for candidate in _default_wordlist_candidates():
        if os.path.isfile(candidate):
            return candidate
    return ""


def patch_missing_wordlists(cmd):
    if not cmd or not isinstance(cmd, str):
        return cmd, []
    if _has_complex_shell_syntax(cmd):
        return cmd, []
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return cmd, []

    segments, operators = _split_segments(tokens)
    notes = []
    existing = _find_existing_wordlist()
    flags_with_next = {"-w", "--wordlist", "-W"}

    patched_segments = []
    for seg in segments:
        out = list(seg)
        i = 0
        while i < len(out):
            t = out[i]
            lower = t.lower()

            if t in flags_with_next and i + 1 < len(out):
                path = out[i + 1]
                if "/" in path and not os.path.isfile(path) and existing:
                    notes.append(f"wordlist not found: {path} -> using {existing}")
                    out[i + 1] = existing
                i += 2
                continue

            if lower.startswith("--wordlist="):
                path = t.split("=", 1)[1]
                if "/" in path and not os.path.isfile(path) and existing:
                    notes.append(f"wordlist not found: {path} -> using {existing}")
                    out[i] = f"--wordlist={existing}"
                i += 1
                continue

            if lower.startswith("-w") and len(t) > 2 and not lower.startswith("--"):
                path = t[2:]
                if "/" in path and not os.path.isfile(path) and existing:
                    notes.append(f"wordlist not found: {path} -> using {existing}")
                    out[i] = f"-w{existing}"
                i += 1
                continue

            i += 1
        patched_segments.append(out)

    return _join_segments(patched_segments, operators), notes


def enforce_sudo_for_scanners(cmd):
    if not cmd or not isinstance(cmd, str):
        return cmd, False
    if _has_complex_shell_syntax(cmd):
        return cmd, False
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return cmd, False

    segments, operators = _split_segments(tokens)
    changed = False
    patched = []
    for seg in segments:
        if not seg:
            patched.append(seg)
            continue
        tool = _primary_tool_from_tokens(seg)
        if tool in FORCE_SUDO_TOOLS and seg[0] != "sudo":
            patched.append(["sudo", *seg])
            changed = True
        else:
            patched.append(seg)
    if not changed:
        return cmd, False
    return _join_segments(patched, operators), True


def find_missing_local_paths(cmd):
    if not cmd or not isinstance(cmd, str):
        return []
    if _has_complex_shell_syntax(cmd):
        return []
    try:
        tokens = _tokenize_shell(cmd)
    except ValueError:
        return []

    segments, _ = _split_segments(tokens)
    missing = []
    seen = set()
    for seg in segments:
        if seg and seg[0] in {"test", "["}:
            for j, tok in enumerate(seg):
                if tok in {"-f", "-e", "-d"} and j + 1 < len(seg):
                    path = _normalize_path_token(seg[j + 1])
                    if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                        continue
                    if _looks_like_local_path(path) and not os.path.exists(path):
                        if path not in seen:
                            seen.add(path)
                            missing.append(path)
        i = 0
        while i < len(seg):
            tok = seg[i]
            if tok in PATH_FLAG_VALUES and i + 1 < len(seg):
                path = _normalize_path_token(seg[i + 1])
                if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                    i += 2
                    continue
                if _looks_like_local_path(path) and not os.path.exists(path):
                    if path not in seen:
                        seen.add(path)
                        missing.append(path)
                i += 2
                continue

            if tok.startswith(("-w", "-W")) and len(tok) > 2 and not tok.startswith("--"):
                path = _normalize_path_token(tok[2:])
                if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                    i += 1
                    continue
                if _looks_like_local_path(path) and not os.path.exists(path):
                    if path not in seen:
                        seen.add(path)
                        missing.append(path)
                i += 1
                continue

            if tok.startswith("--wordlist="):
                path = _normalize_path_token(tok.split("=", 1)[1])
                if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                    i += 1
                    continue
                if _looks_like_local_path(path) and not os.path.exists(path):
                    if path not in seen:
                        seen.add(path)
                        missing.append(path)
                i += 1
                continue
            i += 1
    return missing
