#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import json
import os
import re
import shutil
import subprocess
import time
from functools import lru_cache
from urllib.parse import quote_plus

import requests

SERVICE_LINE_RE = re.compile(r"^\s*(\d{1,5})/(?:tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)
SERVER_HEADER_RE = re.compile(r"^\s*server:\s*([^\n\r]+)$", re.IGNORECASE | re.MULTILINE)
VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9._+-]{1,40}[ \t]+\d[\w._:-]*)")
REMOTE_TIMEOUT = (2, 4)
REMOTE_MAX_QUERIES = 2
REMOTE_MAX_ITEMS = 2
REMOTE_ENABLED = os.environ.get("EVA_REMOTE_VULN_INTEL", "1").strip().lower() in {"1", "true", "yes", "on"}
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "").strip()
AUTO_REFRESH_SEARCHSPLOIT = os.environ.get("EVA_AUTO_REFRESH_SEARCHSPLOIT", "1").strip().lower() in {"1", "true", "yes", "on"}
SEARCHSPLOIT_REFRESH_HOURS = int(os.environ.get("EVA_SEARCHSPLOIT_REFRESH_HOURS", "24"))
_LAST_REFRESH_TS = 0.0


def _dedupe_keep_order(items):
    out = []
    seen = set()
    for item in items:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _extract_lookup_queries(last_output, max_queries=4):
    if not last_output:
        return []

    blob = str(last_output)
    queries = []

    for line in blob.splitlines():
        m = SERVICE_LINE_RE.search(line)
        if not m:
            continue
        svc = m.group(2).strip()
        banner = (m.group(3) or "").strip()
        if banner:
            if len(banner) > 90:
                banner = banner[:90]
            queries.append(f"{svc} {banner}")
        else:
            queries.append(svc)

    for m in SERVER_HEADER_RE.finditer(blob):
        val = m.group(1).strip()
        if val:
            queries.append(val)

    for m in VERSION_RE.finditer(blob):
        val = m.group(1).strip()
        if "\n" in val or "\r" in val:
            continue
        if len(val.split()) >= 2:
            head = val.split()[0].upper()
            if head in {"PORT", "STATE", "SERVICE", "VERSION", "NMAP", "HOST"}:
                continue
            queries.append(val)

    queries = _dedupe_keep_order(q.strip() for q in queries if q and len(q.strip()) >= 3)
    return queries[:max_queries]


def _is_specific_query(query):
    if not query:
        return False
    if len(query) < 5 or len(query) > 90:
        return False
    has_alpha = any(ch.isalpha() for ch in query)
    has_digit = any(ch.isdigit() for ch in query)
    return has_alpha and has_digit


def _parse_searchsploit_json(payload):
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []

    hits = []
    for section in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        for item in data.get(section, [])[:5]:
            title = str(item.get("Title", "")).strip()
            path = str(item.get("Path", "")).strip()
            if title and path:
                hits.append(f"{title} [{path}]")
            elif title:
                hits.append(title)
    return _dedupe_keep_order(hits)[:3]


def _refresh_searchsploit_once():
    global _LAST_REFRESH_TS
    if not AUTO_REFRESH_SEARCHSPLOIT:
        return
    if not shutil.which("searchsploit"):
        return
    now = time.time()
    if _LAST_REFRESH_TS and (now - _LAST_REFRESH_TS) < (SEARCHSPLOIT_REFRESH_HOURS * 3600):
        return
    _LAST_REFRESH_TS = now
    try:
        subprocess.run(
            ["searchsploit", "-u"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return


@lru_cache(maxsize=64)
def _searchsploit_hits_for_query(query):
    if not shutil.which("searchsploit"):
        return []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            text=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return []

    raw = proc.stdout or proc.stderr or ""
    return _parse_searchsploit_json(raw)


def _nvd_hits_for_query(query):
    if not REMOTE_ENABLED:
        return []

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        + f"?keywordSearch={quote_plus(query)}&resultsPerPage={REMOTE_MAX_ITEMS}"
    )
    try:
        resp = requests.get(url, timeout=REMOTE_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    items = []
    for vuln in data.get("vulnerabilities", [])[:REMOTE_MAX_ITEMS]:
        cve = vuln.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        if cve_id:
            items.append(cve_id)
    return _dedupe_keep_order(items)


def _vulners_hits_for_query(query):
    if not REMOTE_ENABLED or not VULNERS_API_KEY:
        return []

    url = (
        "https://vulners.com/api/v3/search/lucene/"
        + f"?query={quote_plus(query)}&size={REMOTE_MAX_ITEMS}&apiKey={quote_plus(VULNERS_API_KEY)}"
    )
    try:
        resp = requests.get(url, timeout=REMOTE_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    items = []
    search_results = data.get("data", {}).get("search", [])
    for item in search_results[:REMOTE_MAX_ITEMS]:
        source = item.get("_source", {})
        ident = str(source.get("id", "")).strip()
        if ident:
            items.append(ident)
    return _dedupe_keep_order(items)


def build_vuln_intel_context(last_output):
    queries = _extract_lookup_queries(last_output)
    if not queries:
        return ""
    _refresh_searchsploit_once()

    local_lines = []
    for q in queries:
        hits = _searchsploit_hits_for_query(q)
        if hits:
            local_lines.append(f"{q} => {' | '.join(hits)}")

    remote_lines = []
    for q in [q for q in queries if _is_specific_query(q)][:REMOTE_MAX_QUERIES]:
        hits = _nvd_hits_for_query(q)
        if hits:
            remote_lines.append(f"{q} => {', '.join(hits)}")
    vulners_lines = []
    for q in [q for q in queries if _is_specific_query(q)][:REMOTE_MAX_QUERIES]:
        hits = _vulners_hits_for_query(q)
        if hits:
            vulners_lines.append(f"{q} => {', '.join(hits)}")

    chunks = [f"VULN_QUERIES={' || '.join(queries)}"]
    chunks.append("SEARCHSPLOIT_AVAILABLE=yes" if shutil.which("searchsploit") else "SEARCHSPLOIT_AVAILABLE=no")
    if local_lines:
        chunks.append(f"SEARCHSPLOIT_HITS={' || '.join(local_lines)}")
    if REMOTE_ENABLED:
        chunks.append("REMOTE_CVE_SOURCE=nvd")
        if remote_lines:
            chunks.append(f"NVD_CVE_HITS={' || '.join(remote_lines)}")
        chunks.append("VULNERS_SOURCE=enabled" if VULNERS_API_KEY else "VULNERS_SOURCE=disabled_no_api_key")
        if vulners_lines:
            chunks.append(f"VULNERS_HITS={' || '.join(vulners_lines)}")
    else:
        chunks.append("REMOTE_CVE_SOURCE=disabled")

    return "\n".join(chunks)
