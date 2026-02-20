#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import re
import shutil
from pathlib import Path

from modules.vuln_intel import build_vuln_intel_context


PORT_SERVICE_RE = re.compile(r"(\d{1,5})/tcp\s+open\s+([^\s]+)", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,}\b")


def _latest_command_output(timeline):
    latest = ""
    for item in timeline:
        if item.get("type") == "command":
            latest = str(item.get("output", ""))
    return latest


def _signals_from_output(output):
    services = [f"{svc}/{port}" for port, svc in PORT_SERVICE_RE.findall(output or "")]
    ips = IP_RE.findall(output or "")
    hosts = []
    for h in HOST_RE.findall(output or ""):
        if h.replace(".", "").isdigit():
            continue
        if not h[0].isalpha():
            continue
        hosts.append(h)
    return {
        "services": services[:8],
        "ips": ips[:8],
        "hosts": hosts[:8],
    }


def _recent_commands(timeline, count=4):
    cmds = [str(item.get("cmd", "")) for item in timeline if item.get("type") == "command"]
    return cmds[-count:]


def _service_priority(services):
    names = [svc.split("/")[0].lower() for svc in services]
    for svc in ("ftp", "http", "https", "smb", "ssh", "mysql"):
        if svc in names:
            return svc
    return names[0] if names else "unknown"


def _detect_package_manager():
    for manager in ("apt-get", "dnf", "yum", "pacman", "zypper", "brew"):
        if shutil.which(manager):
            return manager
    return "unknown"


def _tool_capabilities():
    tools = [
        "curl", "wget", "nmap", "masscan", "nikto", "ffuf", "gobuster",
        "searchsploit", "nuclei", "python3",
    ]
    states = []
    for tool in tools:
        states.append(f"{tool}:{'yes' if shutil.which(tool) else 'no'}")
    return ", ".join(states)


def _wordlist_inventory():
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/rockyou.txt",
    ]
    existing = [p for p in candidates if Path(p).is_file()]
    return ", ".join(existing) if existing else "none"


def infer_stage(timeline, last_output=""):
    out = last_output or _latest_command_output(timeline)
    low = out.lower()
    has_cmd = any(item.get("type") == "command" for item in timeline)
    if not has_cmd:
        return "RECON"
    if "open http" in low or "nginx" in low or "apache" in low or "title:" in low:
        return "WEB_ENUM"
    if "ftp" in low or "ssh" in low or "smb" in low:
        return "SERVICE_ENUM"
    if "cve-" in low or "vulnerable" in low:
        return "VULN_RESEARCH"
    if "uid=" in low or "root" in low or "reverse shell" in low:
        return "POST_ACCESS"
    return "ENUMERATION"


def build_workflow_context(timeline, last_output=""):
    out = last_output or _latest_command_output(timeline)
    signals = _signals_from_output(out)
    stage = infer_stage(timeline, out)
    focus_map = {
        "RECON": "Discover live hosts and exposed services quickly.",
        "ENUMERATION": "Refine findings and remove noise in service data.",
        "SERVICE_ENUM": "Deep-check identified service attack surface and auth paths.",
        "WEB_ENUM": "Map routes, vhosts, auth points, and interesting app tech.",
        "VULN_RESEARCH": "Validate plausible CVEs against exact detected versions.",
        "POST_ACCESS": "Stabilize access, enumerate privileges, and gather proof artifacts.",
    }
    focus = focus_map.get(stage, "Continue evidence-driven enumeration.")
    services = ", ".join(signals["services"]) if signals["services"] else "none"
    hosts = ", ".join(signals["hosts"][:5]) if signals["hosts"] else "none"
    ips = ", ".join(signals["ips"][:5]) if signals["ips"] else "none"
    recent = " || ".join(_recent_commands(timeline)) or "none"
    priority = _service_priority(signals["services"])
    avoid_broad_rescan = "true" if signals["services"] else "false"
    vuln_intel = build_vuln_intel_context(out)
    package_manager = _detect_package_manager()
    capabilities = _tool_capabilities()
    wordlists = _wordlist_inventory()
    return (
        f"STAGE={stage}\n"
        f"FOCUS={focus}\n"
        f"SERVICES={services}\n"
        f"PRIMARY_SERVICE={priority}\n"
        f"AVOID_BROAD_RESCAN={avoid_broad_rescan}\n"
        f"RECENT_COMMANDS={recent}\n"
        f"HOSTS={hosts}\n"
        f"IPS={ips}\n"
        f"PACKAGE_MANAGER={package_manager}\n"
        f"TOOLS={capabilities}\n"
        f"WORDLISTS={wordlists}\n"
        "OPSEC=Do not assume local tool paths/wordlists exist. Validate prerequisites first.\n"
        "OUTPUT_POLICY=Keep command output on stdout (no -o output files/redirection).\n"
        "WRITEUP_REQUIREMENT=Keep each step reproducible with command -> evidence -> conclusion."
        + (f"\n{vuln_intel}" if vuln_intel else "")
    )
