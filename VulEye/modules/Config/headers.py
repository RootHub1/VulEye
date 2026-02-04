import requests
from colorama import init, Fore, Style

init(autoreset=True)

def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SECURITY HEADERS CHECKER                              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (http:// or https://): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing security headers for: {target}{Style.RESET_ALL}")

    try:
        response = requests.get(target, timeout=10, verify=False)
        headers = response.headers

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SECURITY HEADERS ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        security_headers = {
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks by controlling allowed resources',
                'severity': 'High',
                'recommendation': 'Implement CSP with strict policies'
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS-only connections',
                'severity': 'High',
                'recommendation': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'Medium',
                'recommendation': 'Set X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'Medium',
                'recommendation': 'Add X-Content-Type-Options: nosniff'
            },
            'X-XSS-Protection': {
                'description': 'Enables XSS filter in browsers',
                'severity': 'Medium',
                'recommendation': 'Add X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information sent',
                'severity': 'Low',
                'recommendation': 'Set Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features (camera, microphone, etc.)',
                'severity': 'Medium',
                'recommendation': 'Implement Permissions-Policy to restrict unnecessary features'
            },
            'Cross-Origin-Opener-Policy': {
                'description': 'Prevents cross-origin window access',
                'severity': 'Low',
                'recommendation': 'Add Cross-Origin-Opener-Policy: same-origin'
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Controls cross-origin resource embedding',
                'severity': 'Low',
                'recommendation': 'Consider Cross-Origin-Embedder-Policy: require-corp'
            },
            'Cross-Origin-Resource-Policy': {
                'description': 'Prevents cross-origin resource loading',
                'severity': 'Low',
                'recommendation': 'Add Cross-Origin-Resource-Policy: same-origin'
            }
        }

        missing_headers = []
        present_headers = []

        for header, info in security_headers.items():
            if header in headers:
                present_headers.append(header)
                print(f"\n{Fore.GREEN}[✓] {header}{Style.RESET_ALL}")
                print(f"   Value: {headers[header][:100]}")
            else:
                missing_headers.append((header, info))
                severity_color = Fore.RED if info['severity'] == 'High' else (
                    Fore.YELLOW if info['severity'] == 'Medium' else Fore.CYAN)
                print(f"\n{severity_color}[✗] MISSING: {header}{Style.RESET_ALL}")
                print(f"   Severity: {info['severity']}")
                print(f"   Description: {info['description']}")
                print(f"   Recommendation: {info['recommendation']}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}Present headers: {len(present_headers)}/10{Style.RESET_ALL}")
        print(f"{Fore.RED}Missing headers: {len(missing_headers)}/10{Style.RESET_ALL}")

        if missing_headers:
            print(f"\n{Fore.YELLOW}[!] Security Recommendations:{Style.RESET_ALL}")
            for header, info in missing_headers:
                severity_color = Fore.RED if info['severity'] == 'High' else (
                    Fore.YELLOW if info['severity'] == 'Medium' else Fore.CYAN)
                print(f"{severity_color}  • {header} ({info['severity']}){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[+] Additional Information:{Style.RESET_ALL}")
        print(f"   Server: {headers.get('Server', 'Not disclosed')}")
        print(f"   Content-Type: {headers.get('Content-Type', 'Not specified')}")

        if 'Set-Cookie' in headers:
            cookies = headers.get('Set-Cookie', '')
            if 'Secure' not in cookies:
                print(f"{Fore.YELLOW}[!] Cookie missing 'Secure' flag{Style.RESET_ALL}")
            if 'HttpOnly' not in cookies:
                print(f"{Fore.YELLOW}[!] Cookie missing 'HttpOnly' flag{Style.RESET_ALL}")
            if 'SameSite' not in cookies:
                print(f"{Fore.YELLOW}[!] Cookie missing 'SameSite' attribute{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No cookies set{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Analysis completed successfully{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")