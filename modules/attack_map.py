#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import json
import os
import platform
import re
import socket
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

####vars
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FQDN_PATTERN = re.compile(r"\b(?=.{4,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
NMAP_SERVICE_PATTERN = re.compile(r"(\d{1,5})/tcp\s+open\s+([^\s]+)", re.IGNORECASE)
NMAP_SERVICE_DETAIL_PATTERN = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)
DOMAIN_USER_PATTERN = re.compile(r"\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.-]+)\b")
UID_NAME_PATTERN = re.compile(r"uid=\d+\(([^)]+)\)")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SERVER_HEADER_PATTERN = re.compile(r"^\s*server:\s*([^\r\n]+)\s*$", re.IGNORECASE | re.MULTILINE)
FTP_BANNER_PATTERN = re.compile(r"^\s*220[- ]([^\r\n]+)\s*$", re.IGNORECASE | re.MULTILINE)



## tutility funcs
def _normalize_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return ip


def _guess_target_os(blob):
    text = blob.lower()

    # --- Windows ---
    if any(word in text for word in [
        "windows", "winrm", "active directory", "smb", "kerberos",
        "powershell", "ntlm", "iis", "msrpc", "netbios",
        "windows server", "microsoft"
    ]):
        return "Windows"

    # --- Linux ---
    if any(word in text for word in [
        "linux", "ubuntu", "debian", "centos", "red hat", "rhel",
        "fedora", "arch linux", "manjaro", "alpine",
        "kali", "parrot", "openssh", "systemd",
        "gnu/linux"
    ]):
        return "Linux"

    # --- macOS ---
    if any(word in text for word in [
        "macos", "darwin", "os x", "mac os", "launchd",
        "xcode", "icloud"
    ]):
        return "macOS"

    # --- BSD ---
    if any(word in text for word in [
        "freebsd", "openbsd", "netbsd", "dragonfly bsd"
    ]):
        return "BSD"

    # --- Android ---
    if any(word in text for word in [
        "android", "dalvik", "art runtime"
    ]):
        return "Android"

    # --- iOS ---
    if any(word in text for word in [
        "ios", "iphone os", "ipad"
    ]):
        return "iOS"

    # --- Network / other stuff ---
    if any(word in text for word in [
        "routeros", "mikrotik", "cisco ios", "juniper",
        "fortigate", "pfsense"
    ]):
        return "Network Device"

    return "Unknown"

def _extract_primary_target(user_lines):
    for line in user_lines:
        for ip in IP_PATTERN.findall(line):
            norm = _normalize_ip(ip)
            if norm:
                return norm
    return None


def _extract_domains(blob):
    found = []
    seen = set()
    for raw in FQDN_PATTERN.findall(blob or ""):
        domain = raw.lower().rstrip(".")
        if domain in {"e.g", "i.e"}:
            continue
        if domain.count(".") < 1:
            continue
        first = domain.split(".", 1)[0]
        if not any(ch.isalpha() for ch in first):
            continue
        if domain not in seen:
            seen.add(domain)
            found.append(domain)
    return found


def _clean_software_label(text):
    if not text:
        return ""
    clean = re.sub(r"\s+", " ", str(text)).strip().strip(".,;:()[]{}")
    if len(clean) < 4 or len(clean) > 96:
        return ""
    low = clean.lower()
    if low in {"unknown", "none", "n/a", "example", "e.g"}:
        return ""
    if re.fullmatch(r"\d+(?:\.\d+)+", clean):
        return ""
    if not any(ch.isalpha() for ch in clean):
        return ""
    return clean


def _software_node_id(host, label):
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:48]
    return f"sw:{host}:{slug or 'unknown'}"


def _operator_fingerprint():
    hostname = socket.gethostname() or "localhost"
    os_name = platform.system() or "Unknown OS"
    release = platform.release() or "Unknown Release"
    arch = platform.machine() or "Unknown"
    cpu = platform.processor() or platform.uname().processor or "Unknown CPU"
    cores = os.cpu_count() or 0
    user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
    label = f"Operator ({hostname})"
    detail = f"User: {user} | OS: {os_name} {release} | Arch: {arch} | CPU: {cpu} | Cores: {cores}"
    return label, detail


######
## create the map vector nodes
#######

def _add_node(nodes, node_id, label, node_type, detail=""):
    if node_id in nodes:
        return
    nodes[node_id] = {
        "id": node_id,
        "label": label,
        "type": node_type,
        "detail": detail,
    }


def _add_edge(edges, src, dst, label, detail=""):
    edge_id = f"{src}->{dst}:{label}"
    if edge_id in edges:
        return
    edges[edge_id] = {
        "id": edge_id,
        "source": src,
        "target": dst,
        "label": label,
        "detail": detail,
    }


def build_attack_graph(session_name, timeline):
    nodes = {}
    edges = {}

    user_lines = [item.get("content", "") for item in timeline if item.get("type") == "user"]
    analysis_lines = [item.get("content", "") for item in timeline if item.get("type") == "analysis"]
    command_items = [item for item in timeline if item.get("type") == "command"]

    primary_target = _extract_primary_target(user_lines + analysis_lines)
    all_analysis = "\n".join(analysis_lines)
    full_blob = "\n".join(user_lines + analysis_lines + [item.get("cmd", "") + "\n" + item.get("output", "") for item in command_items])

    operator_id = "operator"
    op_label, op_detail = _operator_fingerprint()
    _add_node(nodes, operator_id, op_label, "operator", op_detail)

    if primary_target:
        target_id = f"target:{primary_target}"
        target_os = _guess_target_os("\n".join(user_lines) + "\n" + all_analysis)
        _add_node(nodes, target_id, f"Target {primary_target}", "target", f"OS guess: {target_os}")
        _add_edge(edges, operator_id, target_id, "engages", "Initial assessment scope")

    # Add hosts from the session of EVA
    for ip in IP_PATTERN.findall(full_blob):
        norm = _normalize_ip(ip)
        if not norm:
            continue
        if primary_target and norm == primary_target:
            continue
        ip_id = f"host:{norm}"
        _add_node(nodes, ip_id, norm, "host", "Observed in chat/analysis/command artifacts")
        _add_edge(edges, operator_id, ip_id, "observes", "Seen in session artifacts")

    for fqdn in _extract_domains("\n".join(user_lines + [item.get("cmd", "") for item in command_items] + [item.get("output", "") for item in command_items])):
        domain_id = f"domain:{fqdn}"
        _add_node(nodes, domain_id, fqdn, "domain", "Observed DNS/FQDN artifact")
        if primary_target:
            _add_edge(edges, f"target:{primary_target}", domain_id, "resolves", "Target/DNS relationship")

    for item in command_items:
        cmd = item.get("cmd", "")
        out = item.get("output", "")

        mentioned_ips = []
        for ip in IP_PATTERN.findall(cmd + "\n" + out):
            norm = _normalize_ip(ip)
            if norm:
                mentioned_ips.append(norm)

        for ip in mentioned_ips:
            ip_id = f"host:{ip}"
            _add_node(nodes, ip_id, ip, "host", "Host seen in command/output")
            _add_edge(edges, operator_id, ip_id, "scans", cmd[:80])

        parsed_service_line = False
        for line in out.splitlines():
            match = NMAP_SERVICE_DETAIL_PATTERN.search(line)
            if not match:
                continue
            parsed_service_line = True
            port, proto, service, detail = match.groups()
            host = mentioned_ips[0] if mentioned_ips else primary_target
            if not host:
                continue
            host_id = f"host:{host}" if host != primary_target else f"target:{host}"
            detail = (detail or "").strip()
            detail_text = f"Service {service} open on {proto.upper()}/{port}"
            if detail:
                detail_text += f" | {detail}"
            service_id = f"svc:{host}:{port}:{service.lower()}"
            _add_node(
                nodes,
                service_id,
                f"{service}/{port}",
                "service",
                detail_text,
            )
            _add_edge(edges, host_id, service_id, "exposes", f"Derived from `{cmd}`")

            software_label = _clean_software_label(detail)
            if software_label:
                sw_id = _software_node_id(host, software_label)
                _add_node(nodes, sw_id, software_label, "software", f"Detected from service banner on {host}:{port}")
                _add_edge(edges, service_id, sw_id, "runs", "Banner/version fingerprint")

        if not parsed_service_line:
            for port, service in NMAP_SERVICE_PATTERN.findall(out):
                host = mentioned_ips[0] if mentioned_ips else primary_target
                if not host:
                    continue
                host_id = f"host:{host}" if host != primary_target else f"target:{host}"
                service_id = f"svc:{host}:{port}:{service.lower()}"
                _add_node(
                    nodes,
                    service_id,
                    f"{service}/{port}",
                    "service",
                    f"Service {service} open on TCP/{port}",
                )
                _add_edge(edges, host_id, service_id, "exposes", f"Derived from `{cmd}`")

        host_for_banner = mentioned_ips[0] if mentioned_ips else primary_target
        if host_for_banner:
            for label in SERVER_HEADER_PATTERN.findall(out):
                software_label = _clean_software_label(label)
                if not software_label:
                    continue
                sw_id = _software_node_id(host_for_banner, software_label)
                _add_node(nodes, sw_id, software_label, "software", f"HTTP server banner on {host_for_banner}")
                if primary_target:
                    _add_edge(edges, f"target:{primary_target}", sw_id, "fingerprinted", "Header-derived software fingerprint")

            for label in FTP_BANNER_PATTERN.findall(out):
                software_label = _clean_software_label(label)
                if not software_label:
                    continue
                sw_id = _software_node_id(host_for_banner, software_label)
                _add_node(nodes, sw_id, software_label, "software", f"FTP banner on {host_for_banner}")
                if primary_target:
                    _add_edge(edges, f"target:{primary_target}", sw_id, "fingerprinted", "FTP banner-derived software fingerprint")

        for domain, user in DOMAIN_USER_PATTERN.findall(out):
            domain_id = f"domain:{domain.lower()}"
            user_id = f"user:{domain.lower()}\\{user.lower()}"
            _add_node(nodes, domain_id, domain, "domain", "Domain observed in output")
            _add_node(nodes, user_id, f"{domain}\\{user}", "user", "Domain account observed")
            _add_edge(edges, domain_id, user_id, "contains", "Domain principal relationship")
            if primary_target:
                _add_edge(edges, f"target:{primary_target}", user_id, "auth-context", "Credential/artifact linkage")

        for username in UID_NAME_PATTERN.findall(out):
            user_id = f"user:local:{username.lower()}"
            _add_node(nodes, user_id, username, "user", "Linux local account artifact")
            if primary_target:
                _add_edge(edges, f"target:{primary_target}", user_id, "local-user", "uid() account extraction")

        whoami = out.strip().splitlines()
        if len(whoami) == 1 and 0 < len(whoami[0]) <= 32 and " " not in whoami[0]:
            if re.match(r"^[A-Za-z0-9_.\\$-]+$", whoami[0]):
                user_text = whoami[0]
                user_id = f"user:observed:{user_text.lower()}"
                _add_node(nodes, user_id, user_text, "user", "Observed identity output")
                if primary_target:
                    _add_edge(edges, f"target:{primary_target}", user_id, "execution-context", f"From `{cmd}`")

    ordered_commands = [item.get("cmd", "").strip() for item in command_items if item.get("cmd", "").strip()]
    ordered_commands = ordered_commands[-20:]
    previous_step_id = ""
    for idx, cmd in enumerate(ordered_commands, start=1):
        step_id = f"step:{idx}"
        step_label = f"Step {idx}: {cmd[:52]}"
        _add_node(nodes, step_id, step_label, "step", cmd)
        _add_edge(edges, operator_id, step_id, "executes", "Operator command sequence")
        if previous_step_id:
            _add_edge(edges, previous_step_id, step_id, "then", "Workflow progression")
        if primary_target:
            _add_edge(edges, step_id, f"target:{primary_target}", "targets", "Step aimed at target scope")
        previous_step_id = step_id

    cves = []
    seen_cves = set()
    for cve in CVE_PATTERN.findall(full_blob):
        normalized = cve.upper()
        if normalized in seen_cves:
            continue
        seen_cves.add(normalized)
        cves.append(normalized)
    for cve in cves[:20]:
        cve_id = f"cve:{cve}"
        _add_node(nodes, cve_id, cve, "cve", "Vulnerability reference extracted from session artifacts")
        _add_edge(edges, operator_id, cve_id, "researches", "Referenced during workflow")
        if primary_target:
            _add_edge(edges, f"target:{primary_target}", cve_id, "candidate-vuln", "Potential target relevance")

    graph = {
        "meta": {
            "session": session_name,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
    }
    # If no actionable artifact was discovered, keep only the operator node.
    if len(nodes) == 1:
        graph["edges"] = []
        graph["meta"]["edge_count"] = 0
        graph["meta"]["node_count"] = 1
    return graph


def _html_template(graph_json, version="unknown"):
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>EVA Attack Map</title>
  <style>
    :root {{
      --bg:#0b1324;
      --panel:#111d34;
      --panel2:#162645;
      --line:#2e4167;
      --text:#e6eefc;
      --muted:#96a8cc;
      --operator:#2dd4bf;
      --target:#f97316;
      --host:#60a5fa;
      --service:#c084fc;
      --software:#f472b6;
      --user:#22c55e;
      --domain:#facc15;
      --step:#38bdf8;
      --cve:#fb7185;
      --other:#94a3b8;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family:"JetBrains Mono","Consolas",monospace; background:radial-gradient(circle at 20% 0%,#172643,#0b1324 60%); color:var(--text); }}
    .top {{ display:flex; gap:12px; align-items:center; justify-content:space-between; padding:14px 16px; border-bottom:1px solid var(--line); background:rgba(10,16,31,.8); backdrop-filter: blur(8px); position:sticky; top:0; z-index:3; }}
    .title {{ font-size:14px; letter-spacing:.08em; text-transform:uppercase; color:#cde0ff; }}
    .meta {{ color:var(--muted); font-size:12px; }}
    .layout {{ display:grid; grid-template-columns: 1fr 300px; min-height: calc(100vh - 58px); }}
    .canvas-wrap {{ position:relative; overflow:hidden; }}
    svg {{ width:100%; height:100%; display:block; cursor:grab; }}
    .node {{ cursor:pointer; }}
    .node text {{ font-size:11px; fill:var(--text); pointer-events:none; }}
    .node circle {{ stroke:#d9e4ff; stroke-opacity:.35; stroke-width:1.2; }}
    .edge {{ stroke:#8ba5d9; stroke-opacity:.45; stroke-width:1.1; }}
    .edge-label {{ fill:#a6bbe4; font-size:10px; }}
    .side {{ border-left:1px solid var(--line); padding:14px; background:linear-gradient(180deg,var(--panel),var(--panel2)); }}
    .card {{ border:1px solid #22355a; border-radius:10px; padding:10px; margin-bottom:12px; background:rgba(12,20,37,.6); }}
    .label {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; margin-bottom:4px; }}
    .value {{ font-size:13px; line-height:1.4; word-break:break-word; }}
    .legend-item {{ display:flex; align-items:center; gap:8px; font-size:12px; margin:6px 0; }}
    .dot {{ width:10px; height:10px; border-radius:999px; border:1px solid rgba(255,255,255,.4); }}
    .footer {{ color:var(--muted); text-align:center; font-size:12px; padding:10px 14px 16px; border-top:1px solid var(--line); background:rgba(10,16,31,.8); }}
    @media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; }} .side {{ border-left:none; border-top:1px solid var(--line); }} }}
  </style>
</head>
<body>
  <div class=\"top\">
    <div class=\"title\">EVA v{version} 🍎 | Attack Surface Map</div>
    <div class=\"meta\" id=\"meta\"></div>
  </div>
  <div class=\"layout\">
    <div class=\"canvas-wrap\">
      <svg id=\"map\" viewBox=\"0 0 1280 840\" preserveAspectRatio=\"xMidYMid meet\"></svg>
    </div>
    <aside class=\"side\">
      <div class=\"card\">
        <div class=\"label\">Selection</div>
        <div class=\"value\" id=\"sel-title\">None</div>
        <div class=\"label\" style=\"margin-top:8px;\">Details</div>
        <div class=\"value\" id=\"sel-detail\">Click a node or edge.</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Legend</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--operator)\"></span>Operator</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--target)\"></span>Target</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--host)\"></span>Host</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--service)\"></span>Service</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--software)\"></span>Software/Version</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--user)\"></span>User</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--domain)\"></span>Domain</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--step)\"></span>Workflow Step</div>
        <div class=\"legend-item\"><span class=\"dot\" style=\"background:var(--cve)\"></span>CVE Intel</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Navigation</div>
        <div class=\"value\">Drag to pan, wheel to zoom, click node for intel.</div>
      </div>
    </aside>
  </div>
  <div class=\"footer\">EVA v{version}<br/>Made by: Arcangelo</div>

<script>
const graph = {graph_json};
const svg = document.getElementById('map');
const NS = 'http://www.w3.org/2000/svg';
const meta = document.getElementById('meta');
const selTitle = document.getElementById('sel-title');
const selDetail = document.getElementById('sel-detail');

meta.textContent = `${{graph.meta.session}} | ${{graph.meta.generated_at}} | Nodes: ${{graph.meta.node_count}} | Edges: ${{graph.meta.edge_count}} | Made by Arcangelo`;

const typeColor = {{
  operator: getComputedStyle(document.documentElement).getPropertyValue('--operator').trim(),
  target: getComputedStyle(document.documentElement).getPropertyValue('--target').trim(),
  host: getComputedStyle(document.documentElement).getPropertyValue('--host').trim(),
  service: getComputedStyle(document.documentElement).getPropertyValue('--service').trim(),
  software: getComputedStyle(document.documentElement).getPropertyValue('--software').trim(),
  user: getComputedStyle(document.documentElement).getPropertyValue('--user').trim(),
  domain: getComputedStyle(document.documentElement).getPropertyValue('--domain').trim(),
  step: getComputedStyle(document.documentElement).getPropertyValue('--step').trim(),
  cve: getComputedStyle(document.documentElement).getPropertyValue('--cve').trim(),
  other: getComputedStyle(document.documentElement).getPropertyValue('--other').trim(),
}};

const positions = new Map();
const cx = 640, cy = 420, radius = 300;
const nodes = graph.nodes;
nodes.forEach((n, i) => {{
  const ang = (Math.PI * 2 * i) / Math.max(nodes.length, 1);
  positions.set(n.id, {{ x: cx + Math.cos(ang) * radius, y: cy + Math.sin(ang) * radius }});
}});

const gRoot = document.createElementNS(NS, 'g');
svg.appendChild(gRoot);
const gEdges = document.createElementNS(NS, 'g');
const gNodes = document.createElementNS(NS, 'g');
gRoot.appendChild(gEdges);
gRoot.appendChild(gNodes);

function edgeMid(a, b) {{
  return {{ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }};
}}

function draw() {{
  gEdges.innerHTML = '';
  gNodes.innerHTML = '';

  graph.edges.forEach(e => {{
    const a = positions.get(e.source);
    const b = positions.get(e.target);
    if (!a || !b) return;

    const line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    line.setAttribute('class', 'edge');
    line.addEventListener('click', () => {{
      selTitle.textContent = `${{e.label}}`; 
      selDetail.textContent = e.detail || `${{e.source}} -> ${{e.target}}`;
    }});
    gEdges.appendChild(line);

    const mid = edgeMid(a, b);
    const txt = document.createElementNS(NS, 'text');
    txt.setAttribute('x', mid.x + 4);
    txt.setAttribute('y', mid.y - 4);
    txt.setAttribute('class', 'edge-label');
    txt.textContent = e.label;
    gEdges.appendChild(txt);
  }});

  graph.nodes.forEach(n => {{
    const p = positions.get(n.id);
    const group = document.createElementNS(NS, 'g');
    group.setAttribute('class', 'node');

    const circle = document.createElementNS(NS, 'circle');
    circle.setAttribute('cx', p.x);
    circle.setAttribute('cy', p.y);
    circle.setAttribute('r', n.type === 'target' ? 16 : 13);
    circle.setAttribute('fill', typeColor[n.type] || typeColor.other);
    group.appendChild(circle);

    const text = document.createElementNS(NS, 'text');
    text.setAttribute('x', p.x + 16);
    text.setAttribute('y', p.y + 4);
    text.textContent = n.label;
    group.appendChild(text);

    group.addEventListener('click', () => {{
      selTitle.textContent = `${{n.label}} [${{n.type}}]`;
      selDetail.textContent = n.detail || 'No details';
    }});

    enableDrag(group, n.id);
    gNodes.appendChild(group);
  }});
}}

function svgPoint(clientX, clientY) {{
  const pt = svg.createSVGPoint();
  pt.x = clientX;
  pt.y = clientY;
  return pt.matrixTransform(svg.getScreenCTM().inverse());
}}

let dragNode = null;
function enableDrag(group, nodeId) {{
  group.addEventListener('mousedown', (ev) => {{
    dragNode = nodeId;
    ev.stopPropagation();
  }});
}}

window.addEventListener('mousemove', (ev) => {{
  if (!dragNode) return;
  const p = svgPoint(ev.clientX, ev.clientY);
  positions.set(dragNode, {{ x: p.x, y: p.y }});
  draw();
}});
window.addEventListener('mouseup', () => dragNode = null);

let view = {{ x: 0, y: 0, w: 1280, h: 840 }};
let panning = false;
let panStart = null;
svg.addEventListener('mousedown', (ev) => {{
  if (dragNode) return;
  if (ev.button !== 0) return;
  panning = true;
  panStart = {{ mx: ev.clientX, my: ev.clientY, vx: view.x, vy: view.y, vw: view.w, vh: view.h }};
  svg.style.cursor = 'grabbing';
}});
window.addEventListener('mouseup', () => {{
  panning = false;
  svg.style.cursor = 'grab';
}});
window.addEventListener('mousemove', (ev) => {{
  if (!panning) return;
  const panFactor = 0.35;
  const dx = (ev.clientX - panStart.mx) * (panStart.vw / svg.clientWidth) * panFactor;
  const dy = (ev.clientY - panStart.my) * (panStart.vh / svg.clientHeight) * panFactor;
  view.x = panStart.vx - dx;
  view.y = panStart.vy - dy;
  svg.setAttribute('viewBox', `${{view.x}} ${{view.y}} ${{view.w}} ${{view.h}}`);
}});

svg.addEventListener('wheel', (ev) => {{
  ev.preventDefault();
  const scale = ev.deltaY < 0 ? 0.97 : 1.03;
  const oldW = view.w;
  const oldH = view.h;
  const minW = 520, maxW = 4200;
  const minH = 340, maxH = 2800;
  view.w = Math.min(maxW, Math.max(minW, view.w * scale));
  view.h = Math.min(maxH, Math.max(minH, view.h * scale));
  // Keep zoom centered around current view center to avoid jumps.
  view.x += (oldW - view.w) / 2;
  view.y += (oldH - view.h) / 2;
  svg.setAttribute('viewBox', `${{view.x}} ${{view.y}} ${{view.w}} ${{view.h}}`);
}}, {{ passive:false }});

draw();
</script>
</body>
</html>
"""


def generate_attack_map_files(session_name, timeline, maps_dir, version="unknown"):
    maps_dir = Path(maps_dir)
    maps_dir.mkdir(parents=True, exist_ok=True)

    graph = build_attack_graph(session_name, timeline)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"{session_name}_attack_map_{ts}"

    json_path = maps_dir / f"{base}.json"
    html_path = maps_dir / f"{base}.html"

    json_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    html_path.write_text(_html_template(json.dumps(graph), version=version), encoding="utf-8")

    return html_path, json_path, graph


def open_attack_map(path):
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists():
        return False
    return webbrowser.open(file_path.as_uri())
