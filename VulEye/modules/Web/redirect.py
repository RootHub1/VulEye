import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              OPEN REDIRECT SCANNER                                {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL with redirect parameter (e.g., http://site.com/login?redirect=/home): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing URL for redirect parameters{Style.RESET_ALL}")

    parsed = urlparse(target)
    query_params = parse_qs(parsed.query)

    redirect_params = []
    redirect_indicators = ['url', 'redirect', 'next', 'return', 'rurl', 'goto', 'continue', 'view', 'to', 'link']

    for param in query_params.keys():
        if any(ind in param.lower() for ind in redirect_indicators):
            redirect_params.append(param)

    if not redirect_params:
        print(f"\n{Fore.YELLOW}[i] No obvious redirect parameters detected.{Style.RESET_ALL}")
        manual_param = input(
            f"{Fore.YELLOW}Enter parameter name to test manually (e.g., 'redirect'): {Style.RESET_ALL}").strip()
        if manual_param:
            redirect_params = [manual_param]
        else:
            print(f"\n{Fore.RED}[!] No parameter specified. Aborting.{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

    print(f"\n{Fore.GREEN}[✓] Testing redirect parameters: {', '.join(redirect_params)}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}OPEN REDIRECT TESTING RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    test_domains = [
        ("https://example.com", "External HTTPS domain"),
        ("http://example.com", "External HTTP domain"),
        ("//example.com", "Protocol-relative URL"),
        ("///example.com", "Triple-slash bypass attempt"),
        ("javascript:alert(1)", "JavaScript injection attempt"),
        ("data:text/html,<script>alert(1)</script>", "Data URI attempt")
    ]

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in redirect_params:
        print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")

        for payload, description in test_domains:
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{test_query}"

            try:
                response = requests.get(test_url, timeout=8, verify=False, allow_redirects=False)

                redirect_location = response.headers.get('Location', '')
                is_redirect = response.status_code in [301, 302, 303, 307, 308]

                if is_redirect and payload in redirect_location:
                    vulnerable = True
                    print(f"{Fore.RED}[!] VULNERABLE: {param} redirects to external domain{Style.RESET_ALL}")
                    print(f"    Payload: {payload}")
                    print(f"    Description: {description}")
                    print(f"    Status: {response.status_code} → Location: {redirect_location[:80]}")
                    if "javascript:" in payload or "data:" in payload:
                        print(
                            f"    {Fore.MAGENTA}  CRITICAL: Script execution possible via redirect{Style.RESET_ALL}")
                    break

                elif is_redirect and "example.com" in redirect_location:
                    vulnerable = True
                    print(f"{Fore.RED}[!] VULNERABLE: {param} redirects to external domain{Style.RESET_ALL}")
                    print(f"    Payload: {payload}")
                    print(f"    Description: {description}")
                    print(f"    Status: {response.status_code} → Location: {redirect_location[:80]}")
                    break

                elif not is_redirect and ("example.com" in response.text or "window.location" in response.text.lower()):
                    print(f"{Fore.YELLOW}[?] Potential client-side redirect detected{Style.RESET_ALL}")
                    print(f"    Payload: {payload}")
                    print(f"    Check manually for JavaScript-based redirection")

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}OPEN REDIRECT TESTING COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"\n{Fore.RED}[!] OPEN REDIRECT VULNERABILITY CONFIRMED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Risk Level: MEDIUM to HIGH{Style.RESET_ALL}")
        print(f"   • Phishing attacks: attackers can craft trusted-looking links")
        print(f"   • Credential theft via fake login pages")
        print(f"   • Malware distribution through trusted domains")
        print(f"   • Reputation damage to your organization")

        print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
        print(f"   • NEVER use raw user input in redirect URLs")
        print(f"   • Implement allowlist validation:")
        print(f"        allowed = ['/home', '/dashboard', '/profile']")
        print(f"        if redirect not in allowed: redirect = '/default'")
        print(f"   • Use relative paths only (validate no '://' in input)")
        print(f"   • For external redirects, require explicit confirmation page")
        print(f"   • Sanitize with:")
        print(f"        from urllib.parse import urlparse")
        print(f"        if urlparse(user_input).scheme: abort()")
        print(f"   • Add security warning before external redirects")
    else:
        print(f"\n{Fore.GREEN}[✓] No obvious Open Redirect vulnerabilities detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Important Notes:{Style.RESET_ALL}")
        print(f"   • This test checks common bypasses only")
        print(f"   • Test with authenticated sessions")
        print(f"   • Check JavaScript-based redirects manually")
        print(f"   • Validate both server-side AND client-side redirection logic")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Open Redirect analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}⚠️  LEGAL REMINDER:{Style.RESET_ALL}")
    print(f"   Redirecting users without consent may violate computer fraud laws.")
    print(f"   Always obtain written authorization before testing.")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")