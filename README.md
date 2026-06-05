# Security Auditor

Automated network security auditing tool. Scans targets for open ports, identifies services, matches CVEs, and generates OWASP-aligned HTML reports.

## Features
- Multi-threaded TCP port scanning
- Service banner grabbing and identification
- CVE matching against known vulnerabilities
- OWASP-aligned HTML reports

## Usage
```bash
python security_auditor.py scanme.org
python security_auditor.py 192.168.1.1 -p 1-65535 -t 100
```

## Requirements
Python 3.8+ (standard library only - no external dependencies)
