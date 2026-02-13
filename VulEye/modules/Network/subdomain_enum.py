import socket
import requests
import threading
import random
import string
import time
import re
from queue import Queue
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

THREADS = 25
TIMEOUT = 4
DELAY = 0.2

TAKEOVER_SIGNS = [
    "github.io", "herokuapp.com", "amazonaws.com",
    "cloudfront.net", "azurewebsites.net",
    "netlify.app", "fastly.net"
]

SUBDOMAINS = [
    "www","mail","ftp","admin","api","dev","test","staging",
    "beta","portal","vpn","secure","login","auth","sso",
    "cdn","static","img","media","blog","shop","support",
    "docs","wiki","status","dashboard","cpanel","webmail"
]

results = {
    "domain": None,
    "time": None,
    "wildcard": False,
    "subdomains": [],
    "issues": [],
    "attack_surface": []
}


def banner(title):
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}{title.center(70)}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

def random_sub(domain):
    r = ''.join(random.choices(string.ascii_lowercase, k=12))
    return f"{r}.{domain}"

def wildcard_check(domain):
    try:
        socket.gethostbyname(random_sub(domain))
        return True
    except Exception:
        return False

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def http_probe(host):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{host}",
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            title = None
            if r.text:
                m = re.search(r"<title>(.*?)</title>", r.text, re.I)
                if m:
                    title = m.group(1)[:60]
            return scheme.upper(), r.status_code, title
        except Exception:
            pass
    return None, None, None


def worker(domain, q, lock):
    while not q.empty():
        sub = q.get()
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)

            cname = None
            try:
                cname = socket.gethostbyname_ex(host)[0]
            except Exception:
                pass

            proto, status, title = http_probe(host)
            rev = reverse_dns(ip)

            risk = "LOW"
            if any(k in sub for k in ["admin", "dev", "test", "stage", "dashboard"]):
                risk = "MEDIUM"

            takeover = False
            if cname:
                for sig in TAKEOVER_SIGNS:
                    if sig in cname:
                        takeover = True
                        risk = "HIGH"
                        results["issues"].append(
                            f"Possible subdomain takeover: {host} → {cname}"
                        )

            with lock:
                results["subdomains"].append({
                    "host": host,
                    "ip": ip,
                    "protocol": proto,
                    "status": status,
                    "title": title,
                    "reverse_dns": rev,
                    "risk": risk,
                    "takeover": takeover
                })

                color = Fore.RED if risk == "HIGH" else (
                        Fore.YELLOW if risk == "MEDIUM" else Fore.GREEN)

                print(f"{color}[✓] {host} → {ip}{Style.RESET_ALL}")
                if proto:
                    print(f"    {proto} {status} | {title or 'No title'}")
                if takeover:
                    print(f"    {Fore.RED}[!] TAKEOVER POSSIBLE{Style.RESET_ALL}")

        except Exception:
            pass
        finally:
            q.task_done()
            time.sleep(DELAY)


def run():
    banner("SUBDOMAIN ENUMERATION — PRO")

    domain = input(f"{Fore.YELLOW}Target domain: {Style.RESET_ALL}").strip()
    if not domain:
        return

    results["domain"] = domain
    results["time"] = str(datetime.utcnow())

    banner("WILDCARD CHECK")
    results["wildcard"] = wildcard_check(domain)
    if results["wildcard"]:
        print(f"{Fore.YELLOW}[!] Wildcard DNS detected (filtering enabled){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] No wildcard DNS detected{Style.RESET_ALL}")

    q = Queue()
    lock = threading.Lock()

    for s in SUBDOMAINS:
        q.put(s)

    banner(f"ENUMERATION ({len(SUBDOMAINS)} SUBDOMAINS)")
    for _ in range(THREADS):
        threading.Thread(target=worker, args=(domain, q, lock), daemon=True).start()

    q.join()

    
    banner("SUMMARY")

    highs = [s for s in results["subdomains"] if s["risk"] == "HIGH"]
    meds = [s for s in results["subdomains"] if s["risk"] == "MEDIUM"]

    print(f"{Fore.GREEN}Found: {len(results['subdomains'])} subdomains{Style.RESET_ALL}")
    print(f"{Fore.RED}High risk: {len(highs)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Medium risk: {len(meds)}{Style.RESET_ALL}")

    if highs:
        results["attack_surface"].append(
            "High-risk subdomains → auth bypass / takeover / admin access"
        )

    if any(s["protocol"] for s in results["subdomains"]):
        results["attack_surface"].append(
            "Web services → XSS / IDOR / auth testing"
        )

    banner("WHERE TO ATTACK NEXT")
    for a in results["attack_surface"]:
        print(f"• {a}")

    banner("DONE")
    print(f"{Fore.GREEN}[✓] Subdomain enumeration completed{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use only with authorization{Style.RESET_ALL}")

if __name__ == "__main__":
    run()