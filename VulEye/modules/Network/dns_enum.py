import socket
import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.name
import dns.reversename
from colorama import Fore, Style, init
from datetime import datetime
import json
import random
import string

init(autoreset=True)


TIMEOUT = 4
SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","test","dev","api","staging",
    "beta","portal","vpn","ns1","ns2","cpanel","webmail"
]
TAKEOVER_SIGNATURES = [
    "github.io", "herokuapp.com", "amazonaws.com",
    "cloudfront.net", "azurewebsites.net", "netlify.app"
]

resolver = dns.resolver.Resolver()
resolver.lifetime = TIMEOUT
resolver.timeout = TIMEOUT


def banner(title):
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}{title.center(70)}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

def safe_resolve(name, rtype):
    try:
        return resolver.resolve(name, rtype)
    except:
        return None


def get_ns(domain):
    ns = []
    answers = safe_resolve(domain, "NS")
    if answers:
        for r in answers:
            ns.append(str(r).rstrip("."))
    return ns

def test_zone_transfer(domain, ns_list):
    for ns in ns_list:
        try:
            ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, lifetime=10))
            return True, zone
        except:
            continue
    return False, None

def dnssec_check(domain):
    try:
        dnskey = safe_resolve(domain, "DNSKEY")
        return dnskey is not None
    except:
        return False

def wildcard_check(domain):
    rand = ''.join(random.choices(string.ascii_lowercase, k=10))
    test = f"{rand}.{domain}"
    try:
        socket.gethostbyname(test)
        return True
    except:
        return False

def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        ans = safe_resolve(rev, "PTR")
        if ans:
            return str(ans[0]).rstrip(".")
    except:
        pass
    return None

def subdomain_enum(domain):
    found = []
    wildcard = wildcard_check(domain)

    for sub in SUBDOMAIN_WORDLIST:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append((host, ip))
        except:
            pass

    return found, wildcard

def takeover_check(cname):
    for sig in TAKEOVER_SIGNATURES:
        if sig in cname:
            return True
    return False


def run():
    banner("DNS ENUMERATION — PRO")

    domain = input(f"{Fore.YELLOW}Target domain: {Style.RESET_ALL}").strip()
    findings = {
        "domain": domain,
        "time": str(datetime.utcnow()),
        "issues": [],
        "records": {},
        "subdomains": [],
        "attack_surface": []
    }

    
    banner("NAME SERVERS")
    ns_list = get_ns(domain)
    for ns in ns_list:
        print(f"{Fore.GREEN}• {ns}{Style.RESET_ALL}")

    
    banner("ZONE TRANSFER")
    axfr, zone = test_zone_transfer(domain, ns_list)
    if axfr:
        findings["issues"].append("CRITICAL: Zone transfer allowed")
        print(f"{Fore.RED}[!] AXFR SUCCESSFUL{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] AXFR restricted{Style.RESET_ALL}")

    
    banner("DNSSEC")
    if dnssec_check(domain):
        print(f"{Fore.GREEN}[✓] DNSSEC enabled{Style.RESET_ALL}")
    else:
        findings["issues"].append("MEDIUM: DNSSEC not enabled")
        print(f"{Fore.YELLOW}[!] DNSSEC not found{Style.RESET_ALL}")

    
    banner("DNS RECORDS")
    for rtype in ["A","AAAA","MX","TXT","CNAME"]:
        ans = safe_resolve(domain, rtype)
        if ans:
            findings["records"][rtype] = []
            for r in ans:
                print(f"{Fore.GREEN}{rtype}: {r}{Style.RESET_ALL}")
                findings["records"][rtype].append(str(r))

    
    banner("SUBDOMAIN ENUMERATION")
    subs, wildcard = subdomain_enum(domain)
    if wildcard:
        findings["issues"].append("INFO: Wildcard DNS detected")

    for host, ip in subs:
        print(f"{Fore.GREEN}{host} → {ip}{Style.RESET_ALL}")
        rev = reverse_dns(ip)
        if rev:
            print(f"   ↳ PTR: {rev}")
        findings["subdomains"].append({"host": host, "ip": ip})

   
    banner("TAKEOVER CHECK")
    for cname in findings["records"].get("CNAME", []):
        if takeover_check(cname):
            findings["issues"].append(f"HIGH: Possible subdomain takeover → {cname}")
            print(f"{Fore.RED}[!] Possible takeover: {cname}{Style.RESET_ALL}")

    
    banner("WHERE TO ATTACK NEXT")
    if subs:
        findings["attack_surface"].append("Web attack surface via subdomains")
        print("• Enumerate web services on discovered subdomains")
    if axfr:
        print("• Full infra mapping via leaked zone")
    if "MX" in findings["records"]:
        print("• Phishing / email misconfig testing")


    with open("dns_enum_report.json", "w") as f:
        json.dump(findings, f, indent=2)

    banner("DONE")
    print(f"{Fore.GREEN}[✓] Report saved: dns_enum_report.json{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use only with authorization{Style.RESET_ALL}")

if __name__ == "__main__":
    run()
