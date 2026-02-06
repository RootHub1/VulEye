import requests
import hashlib
import time
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)

TIMEOUT = 6
session = requests.Session()
session.verify = False
session.headers.update({"User-Agent": "VulEye-API-Scanner/2.0"})

def banner(t):
    print(f"\n{Fore.CYAN}{'='*72}")
    print(f"{Fore.CYAN}{t.center(72)}")
    print(f"{Fore.CYAN}{'='*72}{Style.RESET_ALL}")

def fingerprint(resp):
    return {
        "status": resp.status_code,
        "len": len(resp.text),
        "hash": hashlib.sha256(resp.text.encode(errors="ignore")).hexdigest()
    }

def get_baseline(url):
    r = session.get(url, timeout=TIMEOUT)
    return fingerprint(r)

def discover_endpoints(base):
    banner("API DISCOVERY")
    paths = [
        "/health", "/status", "/version",
        "/swagger.json", "/openapi.json",
        "/graphql", "/admin", "/users"
    ]
    found = []

    for p in paths:
        url = urljoin(base, p)
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code in [200,401,403]:
                found.append(url)
                print(f"{Fore.GREEN}[✓] {url} → {r.status_code}{Style.RESET_ALL}")
        except:
            pass
    return found

def auth_check(endpoint, baseline):
    banner("AUTHENTICATION CONTROL")
    tests = [
        ({}, "no auth"),
        ({"Authorization": "Bearer invalid"}, "invalid bearer"),
    ]

    issues = []
    for headers, label in tests:
        r = session.get(endpoint, headers=headers, timeout=TIMEOUT)
        fp = fingerprint(r)

        if fp["status"] == 200 and fp["hash"] == baseline["hash"]:
            issues.append(f"Possible auth bypass ({label})")
            print(f"{Fore.MAGENTA}[!] POSSIBLE BYPASS → {label}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] Auth enforced ({label}){Style.RESET_ALL}")

    return issues

def graphql_check(url):
    banner("GRAPHQL CHECK")
    payload = {"query": "{__typename}"}
    try:
        r = session.post(url, json=payload, timeout=TIMEOUT)
        if "__typename" in r.text:
            print(f"{Fore.YELLOW}[!] GraphQL introspection hint detected{Style.RESET_ALL}")
            return True
    except:
        pass
    print(f"{Fore.GREEN}[✓] No GraphQL exposure detected{Style.RESET_ALL}")
    return False

def info_disclosure(url, baseline):
    banner("ERROR HANDLING")
    bad = session.get(url + "/nonexistent123", timeout=TIMEOUT)
    fp = fingerprint(bad)

    if fp["len"] > baseline["len"] * 1.5:
        print(f"{Fore.YELLOW}[!] Verbose error response detected{Style.RESET_ALL}")
        return True

    print(f"{Fore.GREEN}[✓] Error handling looks safe{Style.RESET_ALL}")
    return False

def rate_limit(endpoint):
    banner("RATE LIMITING")
    codes = []
    for _ in range(5):
        r = session.get(endpoint, timeout=TIMEOUT)
        codes.append(r.status_code)
        time.sleep(0.3)

    if all(c == 200 for c in codes):
        print(f"{Fore.YELLOW}[!] No rate limiting detected (possible risk){Style.RESET_ALL}")
        return True

    print(f"{Fore.GREEN}[✓] Rate limiting behavior detected{Style.RESET_ALL}")
    return False


def run():
    banner("API SECURITY SCANNER — PRO")

    base = input(f"{Fore.YELLOW}API base URL: {Style.RESET_ALL}").strip()
    if not base.startswith("http"):
        base = "https://" + base

    baseline = get_baseline(base)
    endpoints = discover_endpoints(base)

    if endpoints:
        auth_issues = auth_check(endpoints[0], baseline)
        rate_limit(endpoints[0])

    if any("graphql" in e.lower() for e in endpoints):
        graphql_check([e for e in endpoints if "graphql" in e.lower()][0])

    info_disclosure(base, baseline)

    banner("SUMMARY")
    print(f"{Fore.CYAN}Scan finished. Manual validation recommended.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use Burp / Postman / Nuclei for confirmation.{Style.RESET_ALL}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
