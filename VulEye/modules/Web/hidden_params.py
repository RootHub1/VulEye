import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} HIDDEN PARAMETERS DISCOVERY {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        input()
        return

    session = requests.Session()
    session.verify = False

    try:
        r = session.get(target, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        hidden_params = []

        comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
        for c in comments:
            if any(k in c.lower() for k in ["debug", "admin", "secret", "token", "todo"]):
                hidden_params.append(("HTML Comment", c.strip()[:80], "MEDIUM"))

        js_vars = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*[\"']([^\"']+)[\"']", r.text)
        for k, v in js_vars:
            if any(x in k.lower() for x in ["token", "secret", "key", "password"]):
                risk = "CRITICAL" if any(x in k.lower() for x in ["token", "secret", "password"]) else "HIGH"
                hidden_params.append(("JS Variable", f"{k}={v[:50]}", risk))

        for inp in soup.find_all("input", {"type": "hidden"}):
            name = inp.get("name")
            val = inp.get("value", "")
            if name:
                hidden_params.append(("Hidden Input", f"{name}={val[:50]}", "MEDIUM"))

        for a in soup.find_all("a", href=True):
            q = urlparse(a["href"]).query
            for p in parse_qs(q):
                if any(x in p.lower() for x in ["debug", "admin", "token", "internal"]):
                    hidden_params.append(("URL Parameter", p, "MEDIUM"))

        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if attr.startswith("data-") and len(str(val)) > 10:
                    hidden_params.append(("Data Attribute", f"{attr}={str(val)[:50]}", "LOW"))

        common_files = [
            "/.env", "/config.php", "/settings.php", "/debug.php", "/admin/config"
        ]

        exposed = []
        for f in common_files:
            u = urljoin(target, f)
            try:
                resp = session.get(u, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 50:
                    exposed.append(u)
            except:
                pass

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        for t, v, rsk in hidden_params:
            color = Fore.MAGENTA if rsk == "CRITICAL" else Fore.RED if rsk == "HIGH" else Fore.YELLOW
            print(f"{color}{t}: {v} [{rsk}]{Style.RESET_ALL}")

        for u in exposed:
            print(f"{Fore.MAGENTA}[!] Exposed config: {u}{Style.RESET_ALL}")

        print(f"\nFound parameters: {len(hidden_params)}")
        print(f"Exposed configs: {len(exposed)}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
