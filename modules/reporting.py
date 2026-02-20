#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import html
import re
import subprocess
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
OPEN_SERVICE_PATTERN = re.compile(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?", re.IGNORECASE)
ENV_CRED_PATTERN = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*=\s*([^\s]{4,})")
INLINE_CRED_PATTERN = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_.-]{1,31}):([^\s:]{4,64})\b")


def _first_nonempty_line(text):
    for line in text.splitlines():
        clean = line.strip()
        if clean:
            return clean
    return ""


def _extract_cves(blob):
    seen = []
    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", blob, flags=re.IGNORECASE):
        cve = cve.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def _extract_command_blob(timeline):
    chunks = []
    for item in timeline:
        if item.get("type") != "command":
            continue
        cmd = str(item.get("cmd", "")).strip()
        out = str(item.get("output", "")).strip()
        chunks.append(f"$ {cmd}\n{out}")
    return "\n".join(chunks)


def _extract_credential_artifacts(command_blob):
    hits = []
    seen = set()
    for key, value in ENV_CRED_PATTERN.findall(command_blob):
        low_key = key.lower()
        if "pass" not in low_key and "token" not in low_key and "secret" not in low_key and "key" not in low_key:
            continue
        sample = f"{key}={value[:6]}***"
        if sample not in seen:
            seen.add(sample)
            hits.append(sample)

    for user, pwd in INLINE_CRED_PATTERN.findall(command_blob):
        low_user = user.lower()
        if low_user in {"http", "https", "ftp", "ssh", "smtp", "imap", "mysql", "postgres"}:
            continue
        sample = f"{user}:{pwd[:4]}***"
        if sample not in seen:
            seen.add(sample)
            hits.append(sample)
    return hits


def _extract_priv_esc_artifacts(command_blob):
    artifacts = []
    if re.search(r"euid=0\(root\)", command_blob, flags=re.IGNORECASE):
        artifacts.append("effective UID switched to root")
    if re.search(r"uid=0\(root\)", command_blob, flags=re.IGNORECASE):
        artifacts.append("root shell context observed")
    if re.search(r"\bNOPASSWD\b", command_blob, flags=re.IGNORECASE):
        artifacts.append("sudo NOPASSWD rule observed")
    return artifacts


def _findings_from_timeline(timeline):
    findings = []
    analysis_blob = "\n".join(item.get("content", "") for item in timeline if item.get("type") == "analysis")
    command_blob = _extract_command_blob(timeline)
    all_text = "\n".join([analysis_blob, command_blob]).strip()

    for cve in _extract_cves(all_text):
        findings.append({
            "title": f"Potential exposure related to {cve}",
            "severity": "high",
            "evidence": f"Referenced in session artifacts: {cve}",
            "impact": "Potential compromise if the affected component/version is confirmed on target assets.",
            "recommendation": "Validate affected versions, apply vendor patch guidance, and retest.",
        })

    for item in timeline:
        if item.get("type") != "command":
            continue
        cmd = item.get("cmd", "")
        out = item.get("output", "")

        for port, proto, service, detail in OPEN_SERVICE_PATTERN.findall(out):
            detail = (detail or "").strip()
            evidence = f"Command `{cmd}` reported open service {service} on {port}/{proto.lower()}."
            if detail:
                evidence += f" Detail: {detail}"
            findings.append({
                "title": f"Exposed service detected: {service} on {proto.upper()}/{port}",
                "severity": "info",
                "evidence": evidence,
                "impact": "Open service increases attack surface and may expose known vulnerabilities if outdated or misconfigured.",
                "recommendation": "Confirm necessity, restrict exposure, and patch/harden the service.",
            })

    credential_hits = _extract_credential_artifacts(command_blob)
    if credential_hits:
        findings.append({
            "title": "Credential Material Observed in Session Output",
            "severity": "high",
            "evidence": "Credential-like artifacts observed: " + ", ".join(credential_hits[:5]),
            "impact": "Leaked credentials can allow unauthorized access and lateral movement.",
            "recommendation": "Rotate exposed credentials immediately and remove secrets from logs/artifacts.",
        })

    priv_esc_hits = _extract_priv_esc_artifacts(command_blob)
    if priv_esc_hits:
        findings.append({
            "title": "Privilege Escalation Evidence Detected",
            "severity": "high",
            "evidence": "Session evidence: " + ", ".join(priv_esc_hits),
            "impact": "Elevated privileges indicate significant compromise impact.",
            "recommendation": "Contain host, audit escalation path, and remediate privilege boundary weaknesses.",
        })

    # Deduplicate by title
    dedup = {}
    for f in findings:
        dedup[f["title"]] = f

    ordered = sorted(
        dedup.values(),
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True,
    )
    return ordered[:12]


def _html_findings_rows(findings):
    rows = []
    for idx, f in enumerate(findings, 1):
        rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td><span class='sev sev-{f['severity']}'>{f['severity'].upper()}</span></td>"
            f"<td>{html.escape(f['evidence'])}</td>"
            f"<td>{html.escape(f['impact'])}</td>"
            f"<td>{html.escape(f['recommendation'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _summary_metrics(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def build_html_report(session_name, backend, timeline, version="unknown"):
    findings = _findings_from_timeline(timeline)
    metrics = _summary_metrics(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    user_inputs = [item.get("content", "") for item in timeline if item.get("type") == "user"]
    scope_hint = _first_nonempty_line("\n".join(user_inputs)) or "Not explicitly defined"

    executive = "No explicit findings were derived from current session output." if not findings else (
        f"Assessment identified {len(findings)} potential finding(s), with "
        f"{metrics['critical']} critical and {metrics['high']} high-severity item(s)."
    )

    rows = _html_findings_rows(findings)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>EVA Report - {html.escape(session_name)}</title>
  <style>
    :root {{
      --bg:#f4f7fb;
      --text:#172030;
      --muted:#4e5a70;
      --line:#d8e0ee;
      --brand:#0b5fff;
      --critical:#7f1d1d;
      --high:#b45309;
      --medium:#92400e;
      --low:#1f6d35;
      --info:#0f4c81;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }}
    .cover {{ min-height:100vh; display:grid; place-items:center; padding:32px; background:linear-gradient(135deg,#e8f0ff,#fefcff 50%,#edf7ff); }}
    .cover-card {{ width:min(980px,100%); border:1px solid var(--line); border-radius:16px; background:#fff; padding:32px; box-shadow:0 20px 60px rgba(15,35,80,.08); }}
    .eyebrow {{ color:var(--brand); font-weight:700; letter-spacing:.12em; text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:6px 0 8px; font-size:36px; line-height:1.1; }}
    .meta {{ color:var(--muted); }}
    main {{ width:min(1200px,100%); margin:0 auto; padding:24px 16px 40px; }}
    .section {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:20px; margin:14px 0; }}
    .grid {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; }}
    .metric {{ border:1px solid var(--line); border-radius:10px; padding:10px; text-align:center; }}
    .metric strong {{ display:block; font-size:24px; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th, td {{ border:1px solid var(--line); padding:10px; vertical-align:top; text-align:left; }}
    th {{ background:#f7f9fe; }}
    .sev {{ display:inline-block; padding:4px 8px; border-radius:999px; font-size:12px; font-weight:700; }}
    .sev-critical {{ background:#fee2e2; color:var(--critical); }}
    .sev-high {{ background:#ffedd5; color:var(--high); }}
    .sev-medium {{ background:#fef3c7; color:var(--medium); }}
    .sev-low {{ background:#dcfce7; color:var(--low); }}
    .sev-info {{ background:#dbeafe; color:var(--info); }}
    .footer {{ text-align:center; color:var(--muted); font-size:12px; margin:18px 0 8px; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} }}
  </style>
</head>
<body>
  <section class=\"cover\">
    <div class=\"cover-card\">
      <div class=\"eyebrow\">EVA Vulnerability Assessment Report</div>
      <h1>Offensive Security Assessment</h1>
      <p class=\"meta\">Session: <strong>{html.escape(session_name)}</strong><br/>Generated: <strong>{now}</strong><br/>AI Backend: <strong>{html.escape(backend)}</strong></p>
      <p>This report follows a concise structure aligned with PTES and NIST SP 800-115 reporting expectations and OWASP-style risk communication.</p>
    </div>
  </section>

  <main>
    <section class=\"section\">
      <h2>Executive Summary</h2>
      <p>{html.escape(executive)}</p>
    </section>

    <section class=\"section\">
      <h2>Scope and Methodology</h2>
      <p><strong>Scope hint:</strong> {html.escape(scope_hint)}</p>
      <p>Methodology: Reconnaissance, analysis, validation, and remediation guidance, mapped to common VAPT reporting structure.</p>
    </section>

    <section class=\"section\">
      <h2>Risk Summary</h2>
      <div class=\"grid\">
        <div class=\"metric\"><span>Critical</span><strong>{metrics['critical']}</strong></div>
        <div class=\"metric\"><span>High</span><strong>{metrics['high']}</strong></div>
        <div class=\"metric\"><span>Medium</span><strong>{metrics['medium']}</strong></div>
        <div class=\"metric\"><span>Low</span><strong>{metrics['low']}</strong></div>
        <div class=\"metric\"><span>Info</span><strong>{metrics['info']}</strong></div>
      </div>
    </section>

    <section class=\"section\">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Evidence</th>
            <th>Impact</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="6">No findings extracted yet. Continue the session and regenerate.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class=\"section\">
      <h2>Conclusion</h2>
      <p>Use this report as a working artifact. Validate each potential issue manually before formal risk acceptance or production remediation.</p>
    </section>
    <div class=\"footer\">EVA v{html.escape(str(version))}<br/>Made by: Arcangelo</div>
  </main>
</body>
</html>
"""


def try_generate_pdf(html_path, pdf_path):
    try:
        result = subprocess.run(
            ["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def open_report_file(path):
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists():
        return False
    return webbrowser.open(file_path.as_uri())
