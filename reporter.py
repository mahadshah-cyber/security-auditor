import datetime

class ReportGenerator:
    def __init__(self, target, open_ports, services, vulnerabilities):
        self.target = target
        self.open_ports = open_ports
        self.services = services
        self.vulnerabilities = vulnerabilities

    def generate(self, filename):
        html = self._build_html()
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")

    def _build_html(self):
        risk = "Low"
        if self.vulnerabilities:
            sevs = [v["severity"] for v in self.vulnerabilities]
            if "Critical" in sevs: risk = "Critical"
            elif "High" in sevs: risk = "High"

        html = f'''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Audit Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:Segoe UI,sans-serif;background:#0a0a0f;color:#e0e0e0;padding:2rem;}}
.container{{max-width:1000px;margin:auto;}}
.header{{border-bottom:2px solid #333;padding-bottom:1rem;margin-bottom:2rem;}}
h1{{color:#fff;font-size:2rem;}}
.risk{{padding:0.5rem 1.5rem;border-radius:20px;font-weight:700;display:inline-block;}}
.section{{background:#14141f;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid #2a2a3a;}}
.section h2{{color:#fff;margin-bottom:1rem;}}
table{{width:100%;border-collapse:collapse;}}
th{{padding:0.75rem;border-bottom:2px solid #333;color:#888;font-size:0.75rem;text-align:left;}}
td{{padding:0.75rem;border-bottom:1px solid #1f1f2f;}}
.cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2rem;}}
.card{{background:#14141f;border-radius:12px;padding:1.5rem;text-align:center;border:1px solid #2a2a3a;}}
.card-val{{font-size:2.5rem;font-weight:700;color:#fff;}}
.critical{{color:#ef4444;font-weight:700;}}
.high{{color:#f97316;font-weight:700;}}
.footer{{text-align:center;color:#555;margin-top:2rem;font-size:0.8rem;}}
</style></head>
<body><div class="container">
<div class="header"><h1>Security Audit Report</h1>
<p style="color:#888;">Target: <strong>{self.target}</strong></p>
<span class="risk" style="background:#dc262633;color:#dc2626;border:1px solid #dc2626;">Risk: {risk}</span></div>
<div class="cards">
<div class="card"><div class="card-val">{len(self.open_ports)}</div>Open Ports</div>
<div class="card"><div class="card-val">{len(self.services)}</div>Services</div>
<div class="card"><div class="card-val">{len(self.vulnerabilities)}</div>Vulnerabilities</div>
</div>'''

        if self.open_ports:
            html += '<div class="section"><h2>Open Ports</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>'
            for p in self.open_ports:
                s = self.services.get(p, {"name":"Unknown","banner":""})
                html += f'<tr><td style="font-family:monospace;color:#60a5fa;">{p}/tcp</td><td>{s["name"]}</td><td style="font-family:monospace;font-size:0.8rem;color:#aaa;">{s["banner"][:80]}</td></tr>'
            html += '</table></div>'

        if self.vulnerabilities:
            html += '<div class="section"><h2>Vulnerabilities</h2><table><tr><th>CVE</th><th>Service</th><th>Severity</th><th>Description</th></tr>'
            for v in self.vulnerabilities:
                cls = v["severity"].lower()
                html += f'<tr><td><strong>{v["cve_id"]}</strong></td><td>{v["service"]}</td><td class="{cls}">{v["severity"]}</td><td>{v["description"]}<br><small style="color:#888;">Fix: {v["remediation"]}</small></td></tr>'
            html += '</table></div>'

        html += '<div class="footer">Security Auditor | Generated Report</div></div></body></html>'
        return html
