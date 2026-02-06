import requests
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} CORS MISCONFIGURATION SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        input()
        return

    session = requests.Session()
    session.verify = False

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://target.com.evil.com"
    ]

    vulnerable = False

    try:
        for origin in test_origins:
            r = session.get(target, headers={"Origin": origin}, timeout=8)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            print(f"\nOrigin: {origin}")
            print(f"ACAO: {acao or 'NOT SET'}")
            print(f"ACAC: {acac or 'NOT SET'}")

            if acao == "*" and acac == "true":
                vulnerable = True
                print(f"{Fore.MAGENTA}[!] CRITICAL: * with credentials{Style.RESET_ALL}")
            elif acao == origin:
                vulnerable = True
                if acac == "true":
                    print(f"{Fore.MAGENTA}[!] CRITICAL: reflected origin + credentials{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Reflected origin{Style.RESET_ALL}")
            elif acao:
                print(f"{Fore.GREEN}[✓] Restricted origin{Style.RESET_ALL}")

        r = session.options(target, headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET"
        }, timeout=8)

        print(f"\nPreflight ACAO: {r.headers.get('Access-Control-Allow-Origin', 'NOT SET')}")
        print(f"Preflight ACAM: {r.headers.get('Access-Control-Allow-Methods', 'NOT SET')}")
        print(f"Preflight ACAH: {r.headers.get('Access-Control-Allow-Headers', 'NOT SET')}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if vulnerable:
            print(f"{Fore.MAGENTA}[!] CORS MISCONFIGURATION DETECTED{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No critical CORS issues detected{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
