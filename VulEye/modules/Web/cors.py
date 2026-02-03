import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              CORS MISCONFIGURATION SCANNER                        {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (API endpoint or resource): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing CORS configuration for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CORS TESTING RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        vulnerable = False
        test_origins = [
            ("https://evil.com", "Malicious external domain"),
            ("https://attacker.com", "Secondary malicious domain"),
            ("null", "Null origin (file:// protocol attack)"),
            ("https://target.com.evil.com", "Subdomain confusion attempt")
        ]

        for origin, description in test_origins:
            headers = {'Origin': origin}
            try:
                response = session.get(target, headers=headers, timeout=8, verify=False)
                acao = response.headers.get('Access-Control-Allow-Origin', 'NOT SET')
                acac = response.headers.get('Access-Control-Allow-Credentials', 'false')

                print(f"\n{Fore.CYAN}[→] Testing with Origin: {origin}{Style.RESET_ALL}")
                print(f"    Response ACAO: {acao}")
                print(f"    Response ACAC: {acac}")

                if acao == '*':
                    if acac.lower() == 'true':
                        vulnerable = True
                        print(
                            f"{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL: Wildcard (*) + Credentials = FULL ACCOUNT TAKEOVER{Style.RESET_ALL}")
                        print(f"    Description: {description}")
                        print(f"    Impact: Attackers can steal user sessions via malicious site")
                    else:
                        print(
                            f"{Fore.YELLOW}[!] WARNING: Wildcard (*) origin allowed (safe only for public APIs){Style.RESET_ALL}")
                        print(f"    Description: {description}")
                elif origin.lower() in acao.lower():
                    vulnerable = True
                    print(f"{Fore.RED}[!] VULNERABLE: Origin reflection detected{Style.RESET_ALL}")
                    print(f"    Description: {description}")
                    print(f"    Impact: Attacker can specify any origin and access responses")
                    if acac.lower() == 'true':
                        print(
                            f"{Fore.MAGENTA}{Style.BRIGHT}      CRITICAL: Credentials allowed with reflected origin!{Style.RESET_ALL}")
                elif acao != 'NOT SET':
                    print(f"{Fore.GREEN}[✓] Restricted to: {acao}{Style.RESET_ALL}")

            except requests.exceptions.Timeout:
                print(f"{Fore.YELLOW}[?] Timeout testing origin: {origin}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[?] Error testing origin '{origin}': {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL CORS HEADER ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        final_response = session.get(target, timeout=8, verify=False)
        cors_headers = {
            'Access-Control-Allow-Origin': final_response.headers.get('Access-Control-Allow-Origin', 'NOT SET'),
            'Access-Control-Allow-Credentials': final_response.headers.get('Access-Control-Allow-Credentials',
                                                                           'NOT SET'),
            'Access-Control-Allow-Methods': final_response.headers.get('Access-Control-Allow-Methods', 'NOT SET'),
            'Access-Control-Allow-Headers': final_response.headers.get('Access-Control-Allow-Headers', 'NOT SET'),
            'Access-Control-Max-Age': final_response.headers.get('Access-Control-Max-Age', 'NOT SET'),
            'Access-Control-Expose-Headers': final_response.headers.get('Access-Control-Expose-Headers', 'NOT SET')
        }

        for header, value in cors_headers.items():
            if value != 'NOT SET':
                print(f"{Fore.CYAN}{header}:{Style.RESET_ALL} {value}")
            else:
                print(f"{Fore.YELLOW}{header}:{Style.RESET_ALL} Not configured")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if vulnerable:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL CORS MISCONFIGURATIONS DETECTED{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Risk Level: CRITICAL{Style.RESET_ALL}")
            print(f"   • Session hijacking via malicious websites")
            print(f"   • Full account takeover when credentials are allowed")
            print(f"   • Data theft from authenticated API responses")

            print(f"\n{Fore.YELLOW}Critical Fixes:{Style.RESET_ALL}")
            print(f"   • NEVER reflect arbitrary Origin headers")
            print(f"   • NEVER use wildcard (*) with Access-Control-Allow-Credentials: true")
            print(f"   • Implement strict origin allowlist:")
            print(f"        allowed_origins = ['https://trusted.com', 'https://app.yourdomain.com']")
            print(f"        if request.headers['Origin'] in allowed_origins:")
            print(f"            response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']")
            print(f"   • For public APIs without credentials: use wildcard (*) ONLY if no sensitive data")
            print(f"   • Validate Origin header against regex pattern (avoid substring matching)")
            print(f"   • Remove CORS headers entirely if cross-origin access is not required")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical CORS misconfigurations detected{Style.RESET_ALL}")
            acao = cors_headers['Access-Control-Allow-Origin']
            acac = cors_headers['Access-Control-Allow-Credentials']

            if acao == '*':
                if acac.lower() == 'true':
                    print(
                        f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] WARNING: Wildcard origin with credentials allowed!{Style.RESET_ALL}")
                else:
                    print(
                        f"\n{Fore.YELLOW}[i] Note: Wildcard origin configured (acceptable for public APIs without credentials){Style.RESET_ALL}")
            elif acao != 'NOT SET':
                print(f"\n{Fore.GREEN}[✓] Origin restrictions appear properly configured{Style.RESET_ALL}")

            print(f"\n{Fore.YELLOW}Best Practices:{Style.RESET_ALL}")
            print(f"   • Verify allowlist contains ONLY trusted domains")
            print(f"   • Avoid regex patterns that allow subdomain takeovers (e.g., '*.yourdomain.com')")
            print(f"   • Set Vary: Origin header to prevent cache poisoning")
            print(f"   • Test with authenticated sessions for full coverage")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] CORS analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}⚠️  LEGAL NOTE:{Style.RESET_ALL}")
        print(f"   CORS misconfigurations enable attacks from external domains.")
        print(f"   Always obtain written authorization before testing.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")