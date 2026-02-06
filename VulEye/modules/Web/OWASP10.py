import requests
import urllib.parse
import socket
import ssl
from colorama import Fore, Style, init
from datetime import datetime
import hashlib

init(autoreset=True)

TIMEOUT = 8
session = requests.Session()
session.verify = False
session.headers.update({"User-Agent": "OWASP-Top10-Scanner/1.0"})

results = {}


def banner(title):
    print(f"\n{Fore.CYAN}{'='*78}")
    print(f"{Fore.CYAN}{title.center(78)}")
    print(f"{Fore.CYAN}{'='*78}{Style.RESET_ALL}")

def get_baseline(url):
    r = session.get(url, timeout=TIMEOUT)
    return {
        "status": r.status_code,
        "length": len(r.text),
        "hash": hashlib.sha256(r.text.encode(errors="ignore")).hexdigest(),
        "headers": r.headers
    }


def a01_access_control(url):
    banner("A01: Broken Access Control")
    findings = []

    test_urls = [
        "/admin", "/administrator", "/dashboard", "/api/admin"
    ]

    for path in test_urls:
        r = session.get(urllib.parse.urljoin(url, path), timeout=TIMEOUT)
        if r.status_code in [200, 302]:
            findings.append(f"⚠️ Possible exposed protected path: {path}")

    if findings:
        for f in findings:
            print(f"{Fore.YELLOW}{f}{Style.RESET_ALL}")
        return "POSSIBLE", findings

    print(f"{Fore.GREEN}[✓] No obvious access control issues detected{Style.RESET_ALL}")
    return "NOT DETECTED", []


def a02_crypto(url):
    banner("A02: Cryptographic Failures")
    findings = []

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        findings.append("❌ HTTPS not enforced")
    else:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as s:
                    proto = s.version()
                    if proto in ["TLSv1", "TLSv1.1"]:
                        findings.append(f"⚠️ Weak TLS protocol: {proto}")
        except:
            pass

    if findings:
        for f in findings:
            print(f"{Fore.RED}{f}{Style.RESET_ALL}")
        return "DETECTED", findings

    print(f"{Fore.GREEN}[✓] No cryptographic failures detected{Style.RESET_ALL}")
    return "NOT DETECTED", []


def a03_injection(url, baseline):
    banner("A03: Injection")
    findings = []

    payload = "'\"<>"
    r = session.get(url + f"?test={payload}", timeout=TIMEOUT)

    if payload in r.text and hashlib.sha256(r.text.encode()).hexdigest() != baseline["hash"]:
        findings.append("⚠️ Reflected input detected (possible XSS/Injection)")

    if findings:
        for f in findings:
            print(f"{Fore.YELLOW}{f}{Style.RESET_ALL}")
        return "POSSIBLE", findings

    print(f"{Fore.GREEN}[✓] No injection indicators detected{Style.RESET_ALL}")
    return "NOT DETECTED", []


def a05_misconfig(baseline):
    banner("A05: Security Misconfiguration")
    findings = []

    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]

    for h in required:
        if h not in baseline["headers"]:
            findings.append(f"⚠️ Missing security header: {h}")

    if findings:
        for f in findings:
            print(f"{Fore.YELLOW}{f}{Style.RESET_ALL}")
        return "DETECTED", findings

    print(f"{Fore.GREEN}[✓] No obvious misconfigurations detected{Style.RESET_ALL}")
    return "NOT DETECTED", []


def a06_components(baseline):
    banner("A06: Vulnerable & Outdated Components")
    findings = []

    server = baseline["headers"].get("Server", "")
    if any(v in server.lower() for v in ["apache", "nginx", "iis"]):
        findings.append(f"ℹ️ Server identified: {server} (check version manually)")

    if findings:
        for f in findings:
            print(f"{Fore.CYAN}{f}{Style.RESET_ALL}")
        return "INFO", findings

    return "UNKNOWN", []


def a10_ssrf(url):
    banner("A10: SSRF")
    findings = []

    test = session.get(url + "?url=http://127.0.0.1", timeout=TIMEOUT)
    if test.status_code != 400:
        findings.append("⚠️ URL parameter accepted (possible SSRF vector)")

    if findings:
        for f in findings:
            print(f"{Fore.YELLOW}{f}{Style.RESET_ALL}")
        return "POSSIBLE", findings

    print(f"{Fore.GREEN}[✓] No SSRF indicators detected{Style.RESET_ALL}")
    return "NOT DETECTED", []


def run():
    banner("OWASP TOP 10 SCANNER — PROFESSIONAL")

    target = input(f"{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith("http"):
        target = "https://" + target

    print(f"{Fore.CYAN}[+] Scanning {target}{Style.RESET_ALL}")

    baseline = get_baseline(target)

    results["A01"] = a01_access_control(target)
    results["A02"] = a02_crypto(target)
    results["A03"] = a03_injection(target, baseline)
    results["A05"] = a05_misconfig(baseline)
    results["A06"] = a06_components(baseline)
    results["A10"] = a10_ssrf(target)

    banner("OWASP TOP 10 SUMMARY")

    for k, v in results.items():
        status = v[0]
        color = (
            Fore.RED if status == "DETECTED" else
            Fore.YELLOW if status == "POSSIBLE" else
            Fore.GREEN if status == "NOT DETECTED" else
            Fore.CYAN
        )
        print(f"{color}{k}: {status}{Style.RESET_ALL}")

    banner("IMPORTANT NOTES")
    print(f"{Fore.YELLOW}• NOT DETECTED ≠ NOT VULNERABLE")
    print(f"• POSSIBLE requires manual testing")
    print(f"• Some OWASP categories cannot be automated")
    print(f"• Use Burp/Nuclei for deep validation{Style.RESET_ALL}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
