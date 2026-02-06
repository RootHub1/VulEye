import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} ADVANCED OPEN REDIRECT SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL with params: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        input()
        return

    parsed = urlparse(target)
    params = parse_qs(parsed.query)

    redirect_keys = [
        "redirect", "url", "next", "return", "r", "to",
        "continue", "goto", "dest", "destination", "view"
    ]

    test_params = [p for p in params if any(k in p.lower() for k in redirect_keys)]

    if not test_params:
        manual = input(f"{Fore.YELLOW}No redirect param found. Enter manually: {Style.RESET_ALL}").strip()
        if not manual:
            return
        test_params = [manual]

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    session = requests.Session()
    session.verify = False

    payloads = [
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com/%2e%2e",
        "https:%2f%2fevil.com",
        "https://evil.com@target.com",
        "https://target.com.evil.com",
        "/\\evil.com",
        "/%2f%2fevil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>"
    ]

    vulnerable = False

    print(f"\n{Fore.GREEN}[✓] Parameters to test: {', '.join(test_params)}{Style.RESET_ALL}")

    for param in test_params:
        print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")

        for payload in payloads:
            q = params.copy()
            q[param] = payload
            url = f"{base_url}?{urlencode(q, doseq=True)}"

            try:
                r = session.get(url, timeout=8, allow_redirects=False)
                location = r.headers.get("Location", "")
                refresh = r.headers.get("Refresh", "")
                body = r.text.lower()

                is_redirect = r.status_code in [301, 302, 303, 307, 308]

                if is_redirect and payload.split(":")[0] in location:
                    vulnerable = True
                    print(f"{Fore.RED}[!] SERVER REDIRECT{Style.RESET_ALL}")
                    print(f"    Param: {param}")
                    print(f"    Payload: {payload}")
                    print(f"    Status: {r.status_code}")
                    print(f"    Location: {location[:120]}")
                    break

                if "url=" in refresh.lower():
                    vulnerable = True
                    print(f"{Fore.RED}[!] META REFRESH REDIRECT{Style.RESET_ALL}")
                    print(f"    Payload: {payload}")
                    print(f"    Refresh: {refresh}")
                    break

                js_patterns = [
                    "window.location",
                    "location.href",
                    "document.location",
                    "location.replace"
                ]

                if any(p in body for p in js_patterns):
                    if "evil.com" in body or payload.lower() in body:
                        print(f"{Fore.YELLOW}[!] CLIENT-SIDE REDIRECT (JS){Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        vulnerable = True
                        break

            except Exception:
                continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RESULT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"{Fore.RED}[!] OPEN REDIRECT CONFIRMED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Impact:{Style.RESET_ALL}")
        print(" • Phishing via trusted domain")
        print(" • OAuth token theft")
        print(" • Malware delivery")
        print(" • Trust abuse")

        print(f"\n{Fore.YELLOW}Remediation:{Style.RESET_ALL}")
        print(" • Use allowlist for redirect targets")
        print(" • Reject absolute URLs")
        print(" • Disallow protocol-relative URLs (//)")
        print(" • Validate with urlparse().netloc == ''")
        print(" • Add confirmation page for external redirects")
    else:
        print(f"{Fore.GREEN}[✓] No open redirect detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
