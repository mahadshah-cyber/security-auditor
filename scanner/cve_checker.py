class CveChecker:
    def __init__(self):
        self.db = [
            {"id":"CVE-2024-3094","kw":"ssh","sev":"Critical","desc":"SSH RCE in XZ Utils","fix":"Update XZ Utils 5.6.1+"},
            {"id":"CVE-2023-44487","kw":"http/2","sev":"High","desc":"HTTP/2 Rapid Reset Attack","fix":"Apply vendor patches"},
            {"id":"CVE-2023-38109","kw":"apache","sev":"Critical","desc":"Apache HTTP Server OOB write","fix":"Upgrade Apache 2.4.58+"},
            {"id":"CVE-2023-50782","kw":"openssh","sev":"Medium","desc":"OpenSSH prefix truncation","fix":"Update OpenSSH 9.6+"},
            {"id":"CVE-2024-0204","kw":"openssl","sev":"High","desc":"OpenSSL use-after-free","fix":"Update OpenSSL 3.2.1+"},
        ]

    def check(self, services):
        findings = []
        for port, svc in services.items():
            combined = (svc["name"] + " " + svc["banner"]).lower()
            for cve in self.db:
                if cve["kw"] in combined:
                    findings.append({"port":port,"service":svc["name"],"cve_id":cve["id"],
                                     "severity":cve["sev"],"description":cve["desc"],"remediation":cve["fix"]})
        return findings
