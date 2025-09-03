
import os
import re
from html import escape
from dns_abuse_integration import generate_dns_section

def run_triage_report(findevil_path, proc_v_path, timeline_path, output_path):
    suspicious_pids = {}
    with open(findevil_path, "r", encoding="utf-8") as f:
        for line in f:
            if any(tag in line for tag in ["YR_RANSOMWARE", "YR_HACKTOOL", "PE_INJECT", "THREAD"]):
                parts = line.strip().split()
                if len(parts) >= 5:
                    try:
                        pid = str(int(parts[1]))
                        suspicious_pids[pid] = {
                            "procname": parts[2],
                            "type": parts[3],
                            "address": parts[4],
                            "desc": " ".join(parts[5:])
                        }
                    except ValueError:
                        continue

    matches = []
    with open(proc_v_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        for pid in suspicious_pids:
            if re.search(rf"\b{pid}\b", line):
                context = [lines[i].strip()]
                for j in range(1, 5):
                    if i + j < len(lines):
                        next_line = lines[i + j].strip()
                        if next_line != "" and not next_line.startswith("-"):
                            context.append(next_line)
                matches.append({
                    "PID": pid,
                    **suspicious_pids[pid],
                    "Details": "\n".join(context)
                })
                break

    timeline_hits = []
    if timeline_path and os.path.exists(timeline_path):
        with open(timeline_path, "r", encoding="utf-8") as f:
            timeline_lines = f.readlines()
        for line in timeline_lines:
            for pid in suspicious_pids:
                if re.search(rf"\b{pid}\b", line):
                    match = re.search(r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(?P<ppid>\d+)\s+(?P<user>\S+)\s+(?P<path>\\Device.*)", line)
                    if match:
                        timeline_hits.append({
                            "pid": pid,
                            "timestamp": match.group("timestamp"),
                            "ppid": match.group("ppid"),
                            "user": match.group("user"),
                            "path": match.group("path")
                        })
                    else:
                        timeline_hits.append({
                            "pid": pid,
                            "timestamp": line[:19],
                            "ppid": "Unknown",
                            "user": "Unknown",
                            "path": line.strip()
                        })

    seen = set()
    triage_section = "<h2>Triage Results</h2><ul>"
    details_section = "<h2>Details</h2>"
    timeline_section = "<h2>Timeline: Who Launched What</h2><ul>"

    for row in matches:
        pid = row["PID"]
        if pid in seen:
            continue
        seen.add(pid)
        triage_section += f"<li>{escape(row['procname'])} (PID {pid})<br>"                           f"&nbsp;&nbsp;↳ Type: {escape(row['type'])}<br>"                           f"&nbsp;&nbsp;↳ Address: {escape(row['address'])}<br>"                           f"&nbsp;&nbsp;↳ Description: {escape(row['desc'])}</li>"
        details_section += f"<h3>{escape(row['procname'])} (PID {pid})</h3><pre>{escape(row['Details'])}</pre>"

    triage_section += "</ul>"

    for hit in timeline_hits:
        timeline_section += f"<li>[{escape(hit['timestamp'])}] PID {hit['pid']} launched by PID {hit['ppid']}<br>"                             f"&nbsp;&nbsp;↳ User: {escape(hit['user'])}<br>"                             f"&nbsp;&nbsp;↳ Path: {escape(hit['path'])}</li>"

    timeline_section += "</ul>"

    dns_path = "M:/misc/view/txt/sys/net/dns/dns.txt"
    dns_section = generate_dns_section(dns_path)

    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Memory Triage Report</title>
    <style>
        body {{ font-family: monospace; background: #f9f9f9; padding: 20px; }}
        h2 {{ color: #333; border-bottom: 1px solid #ccc; }}
        pre {{ background: #fff; padding: 10px; border: 1px solid #ddd; }}
    </style>
</head>
<body>
    <h1>🧠 Memory Triage Report</h1>
    {triage_section}
    {details_section}
    {timeline_section}
    {dns_section}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
