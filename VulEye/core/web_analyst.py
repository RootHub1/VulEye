import requests
import urllib.parse
import socket
import ssl
import time
import hashlib
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

TIMEOUT = 8
session = requests.Session()
session.verify = False
session.headers.update({"User-Agent": "VulEye-Recon/1.0"})


def banner(t):
    print(f"\n{Fore.CYAN}{'='*72}")
    print(f"{Fore.CYAN}{t.center(72)}")
    print(f"{Fore.CYAN}{'='*72}{Style.RESET_ALL}")

def hash_body(text):
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()


def get_baseline(url):
    r = session.get(url, timeout=TIMEOUT)
    return {
        "status": r.status_code,
        "length": len(r.text),
        "hash": hash_body(r.text),
        "headers": r.headers
    }


def detect_tech(url, baseline):
    banner("TECHNOLOGY & CMS DETECTION")
    findings = []

    headers = baseline["headers"]
    body = session.get(url).text.lower()

    if "server" in headers:
        findings.append(f"Server: {headers['Server']}")

    if "x-powered-by" in headers:
        findings.append(f"Framework: {headers['X-Powered-By']}")

    cms = []
    if "/wp-content/" in body:
        cms.append("WordPress (high confidence)")
    if "/sites/default/" in body:
        cms.append("Drupal (medium confidence)")
    if "joomla" in body:
        cms.append("Joomla (low confidence)")

    for c in cms:
        findings.append(f"CMS: {c}")

    for f in findings:
        print(f"{Fore.GREEN}[✓] {f}{Style.RESET_ALL}")

    return findings


def ssl_analysis(url):
    banner("SSL / TLS ANALYSIS")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        print(f"{Fore.YELLOW}[!] HTTPS not used{Style.RESET_ALL}")
        return []

    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as s:
                proto = s.version()
                cipher = s.cipher()
                findings.append(f"Protocol: {proto}")
                findings.append(f"Cipher: {cipher[0]} ({cipher[2]} bits)")

                if proto in ["TLSv1", "TLSv1.1"]:
                    findings.append("⚠️ Weak TLS protocol")

        for f in findings:
            color = Fore.RED if "Weak" in f else Fore.GREEN
            print(f"{color}{f}{Style.RESET_ALL}")

    except Exception as e:
        findings.append(f"SSL error: {e}")

    return findings


def security_headers(baseline):
    banner("SECURITY HEADERS")
    headers = baseline["headers"]
    required = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    missing = []
    for h in required:
        if h not in headers:
            missing.append(h)
            print(f"{Fore.YELLOW}[!] Missing: {h}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] {h}{Style.RESET_ALL}")

    return missing


def vuln_hints(url, baseline):
    banner("SAFE VULNERABILITY HINTS")
    hints = []

    
    payload = "<vuleye>"
    test = session.get(url + f"?v={payload}", timeout=TIMEOUT)
    if payload in test.text and hash_body(test.text) != baseline["hash"]:
        hints.append("Possible reflected input (manual XSS testing advised)")
        print(f"{Fore.YELLOW}[!] Reflected input detected{Style.RESET_ALL}")

    
    if "?" in url:
        lfi = session.get(url + "../../../../etc/passwd", timeout=TIMEOUT)
        if "root:x" in lfi.text:
            hints.append("Possible LFI (confirm manually)")
            print(f"{Fore.RED}[!] LFI indicator found{Style.RESET_ALL}")

    return hints


def run():
    banner("COMPREHENSIVE WEB ANALYZER — PRO")

    target = input(f"{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith("http"):
        target = "https://" + target

    print(f"{Fore.CYAN}[+] Recon on {target}{Style.RESET_ALL}")

    baseline = get_baseline(target)

    tech = detect_tech(target, baseline)
    ssl_findings = ssl_analysis(target)
    missing_headers = security_headers(baseline)
    hints = vuln_hints(target, baseline)

    banner("INTELLIGENT SUMMARY")

    print(f"{Fore.MAGENTA}LIKELY ATTACK SURFACE:{Style.RESET_ALL}")
    for t in tech:
        print(f" • {t}")

    if missing_headers:
        print(f"\n{Fore.YELLOW}CONFIGURATION ISSUES:{Style.RESET_ALL}")
        for h in missing_headers:
            print(f" • Missing {h}")

    if hints:
        print(f"\n{Fore.RED}MANUAL TESTING REQUIRED:{Style.RESET_ALL}")
        for h in hints:
            print(f" • {h}")

    print(f"\n{Fore.CYAN}NEXT TOOLS:{Style.RESET_ALL}")
    print(" • Burp Suite (manual validation)")
    print(" • Nuclei (template-based checks)")
    print(" • CMS-specific scanners")

    banner("DONE")
    print(f"{Fore.GREEN}[✓] Recon finished (no exploitation performed){Style.RESET_ALL}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
