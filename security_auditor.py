#!/usr/bin/env python3
import argparse
from scanner import PortScanner, ServiceDetector, CveChecker
from reporter import ReportGenerator

def main():
    p = argparse.ArgumentParser(description="Security Auditor - Network Security Scanner")
    p.add_argument("target", help="Target IP or hostname")
    p.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    p.add_argument("-t", "--threads", type=int, default=50, help="Thread count")
    p.add_argument("-o", "--output", default="report.html", help="Output report file")
    args = p.parse_args()

    print(f"[*] Scanning {args.target} ports {args.ports}...")
    scanner = PortScanner(args.target, args.ports, args.threads)
    open_ports = scanner.scan()

    if not open_ports:
        print("[!] No open ports found.")
        return

    print(f"[+] Found {len(open_ports)} open ports")
    services = ServiceDetector(args.target).detect(open_ports)
    vulns = CveChecker().check(services)
    print(f"[+] Found {len(vulns)} potential vulnerabilities")
    ReportGenerator(args.target, open_ports, services, vulns).generate(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()
