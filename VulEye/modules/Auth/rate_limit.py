import requests
import time
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              RATE LIMITING CHECKER                                {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (login/registration endpoint): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing rate limiting for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}INITIAL REQUEST ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        test_data = {'username': 'test_user', 'password': 'test_pass'}
        try:
            response = session.post(target, data=test_data, timeout=10, verify=False)
            print(f"\n{Fore.GREEN}[✓] Initial request successful{Style.RESET_ALL}")
            print(f"    Status Code: {response.status_code}")
            print(f"    Response Length: {len(response.text)} bytes")

            rate_headers = [
                'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
                'Retry-After', 'X-Retry-After', 'RateLimit-Limit', 'RateLimit-Remaining'
            ]

            found_headers = []
            print(f"\n{Fore.CYAN}Rate Limit Headers:{Style.RESET_ALL}")
            for header in rate_headers:
                if header in response.headers:
                    value = response.headers[header]
                    found_headers.append((header, value))
                    print(f"   {Fore.GREEN}• {header}:{Style.RESET_ALL} {value}")

            if not found_headers:
                print(f"   {Fore.YELLOW}• No rate limiting headers detected{Style.RESET_ALL}")

            if 'www-authenticate' in response.headers:
                print(f"\n{Fore.CYAN}Authentication Headers:{Style.RESET_ALL}")
                print(f"   • WWW-Authenticate: {response.headers['www-authenticate']}")

        except Exception as e:
            print(f"\n{Fore.YELLOW}[?] Initial request failed: {str(e)[:60]}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Proceeding with rate limit testing anyway...{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RATE LIMIT TESTING (SAFE MODE)")
        print(f"{Fore.YELLOW}Note: Limited to 10 requests to avoid triggering alarms{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Sending 10 rapid authentication requests...{Style.RESET_ALL}")

        results = []
        rate_limited = False
        lockout_triggered = False
        start_time = time.time()

        for i in range(1, 11):
            try:
                test_data = {'username': f'test_user_{i}', 'password': 'invalid_pass'}
                response = session.post(target, data=test_data, timeout=8, verify=False)

                status = response.status_code
                length = len(response.text)
                headers_found = []

                if 'retry-after' in response.headers:
                    headers_found.append(f"Retry-After: {response.headers['retry-after']}")
                    rate_limited = True

                if status in [429, 403, 401]:
                    if status == 429:
                        rate_limited = True
                        status_text = f"{Fore.MAGENTA}429 Too Many Requests{Style.RESET_ALL}"
                    elif status == 403:
                        lockout_triggered = True
                        status_text = f"{Fore.RED}403 Forbidden (Possible lockout){Style.RESET_ALL}"
                    else:
                        status_text = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
                else:
                    status_text = f"{Fore.GREEN}{status}{Style.RESET_ALL}"

                results.append({
                    'request': i,
                    'status': status,
                    'length': length,
                    'headers': headers_found,
                    'rate_limited': rate_limited,
                    'lockout': lockout_triggered
                })

                print(f"   Request #{i:2d}: Status {status_text} | Length: {length:4d} bytes", end="")
                if headers_found:
                    print(f" | {', '.join(headers_found)}", end="")
                print()

                time.sleep(0.3)

            except requests.exceptions.Timeout:
                print(f"   Request #{i:2d}: {Fore.RED}TIMEOUT{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"   Request #{i:2d}: {Fore.YELLOW}Error: {str(e)[:30]}{Style.RESET_ALL}")
                break

        elapsed = time.time() - start_time
        requests_per_second = len(results) / elapsed if elapsed > 0 else 0

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}TESTING RESULTS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Total requests sent: {len(results)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Test duration: {elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Requests per second: {requests_per_second:.2f} RPS{Style.RESET_ALL}")

        status_codes = {}
        for r in results:
            status = r['status']
            status_codes[status] = status_codes.get(status, 0) + 1

        print(f"\n{Fore.CYAN}Status Code Distribution:{Style.RESET_ALL}")
        for code, count in sorted(status_codes.items()):
            color = Fore.MAGENTA if code == 429 else (Fore.RED if code in [403, 401] else Fore.GREEN)
            print(f"   {color}{code}:{Style.RESET_ALL} {count} responses")

        if rate_limited:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] RATE LIMITING DETECTED{Style.RESET_ALL}")
            print(f"    • Server responded with 429 Too Many Requests and/or Retry-After header")
            print(f"    • Protection mechanism: ACTIVE")
        elif lockout_triggered:
            print(f"\n{Fore.RED}[!] ACCOUNT LOCKOUT DETECTED{Style.RESET_ALL}")
            print(f"    • Server responded with 403 Forbidden after multiple failed attempts")
            print(f"    • Protection mechanism: ACTIVE (account lockout)")
        else:
            print(f"\n{Fore.YELLOW}[!] NO RATE LIMITING DETECTED{Style.RESET_ALL}")
            print(f"    • All {len(results)} requests were accepted without throttling")
            print(f"    • {Fore.RED}CRITICAL RISK: System vulnerable to brute-force attacks{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SECURITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        vulnerabilities = []

        if not rate_limited and not lockout_triggered and len(results) >= 5:
            vulnerabilities.append({
                'severity': 'CRITICAL',
                'issue': 'No Rate Limiting Detected',
                'impact': 'Vulnerable to credential stuffing and brute-force attacks',
                'fix': 'Implement rate limiting (e.g., 5 attempts per 15 minutes per IP/user)'
            })

        if rate_limited and not any('retry-after' in str(r.get('headers', [])) for r in results):
            vulnerabilities.append({
                'severity': 'MEDIUM',
                'issue': 'Rate Limiting Without Retry-After Header',
                'impact': 'Clients cannot determine when to retry legitimate requests',
                'fix': 'Include Retry-After header with 429 responses'
            })

        if len(results) > 0 and results[-1]['status'] == 200:
            vulnerabilities.append({
                'severity': 'HIGH',
                'issue': 'Authentication Endpoint Accepts Invalid Credentials Without Rate Limiting',
                'impact': 'Allows unlimited password guessing attempts',
                'fix': 'Implement progressive delays and account lockout after 5 failed attempts'
            })

        if vulnerabilities:
            print(f"\n{Fore.RED}[!] SECURITY VULNERABILITIES DETECTED{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                severity_color = Fore.MAGENTA if vuln['severity'] == 'CRITICAL' else (
                    Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW)
                print(f"\n{severity_color}• {vuln['issue']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"  Impact: {vuln['impact']}")
                print(f"  Fix: {vuln['fix']}")
        else:
            print(f"\n{Fore.GREEN}[✓] Rate limiting protection appears to be properly configured{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}HARDENING RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}For Web Application Developers:{Style.RESET_ALL}")
        print(f"   • Implement multi-layer rate limiting:")
        print(f"        - Per IP address (network layer)")
        print(f"        - Per user account (application layer)")
        print(f"        - Per endpoint (critical endpoints like /login)")
        print(f"   • Use progressive delays:")
        print(f"        Attempt 1-3: No delay")
        print(f"        Attempt 4-5: 2 second delay")
        print(f"        Attempt 6+: Account lockout for 15 minutes")
        print(f"   • Always return same response time for valid/invalid credentials")
        print(f"        (prevent timing attacks)")
        print(f"   • Implement CAPTCHA after 3 failed attempts")
        print(f"   • Use dedicated security headers:")
        print(f"        X-RateLimit-Limit: 100")
        print(f"        X-RateLimit-Remaining: 99")
        print(f"        X-RateLimit-Reset: 1600000000")
        print(f"        Retry-After: 60")
        print(f"   • Monitor and alert on brute-force patterns")
        print(f"   • Use Web Application Firewall (WAF) rules for additional protection")

        print(f"\n{Fore.YELLOW}For System Administrators:{Style.RESET_ALL}")
        print(f"   • Configure reverse proxy rate limiting (Nginx/Apache):")
        print(f"        Nginx: limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;")
        print(f"   • Implement fail2ban to block repeat offenders at firewall level")
        print(f"   • Use Cloudflare/CloudFront rate limiting features")
        print(f"   • Set up SIEM alerts for brute-force patterns")
        print(f"   • Regularly test rate limiting with tools like this one")

        print(f"\n{Fore.YELLOW}For Pentesters:{Style.RESET_ALL}")
        print(f"   • Always obtain written authorization before rate limit testing")
        print(f"   • Document baseline request rates before testing")
        print(f"   • Test multiple endpoints (login, password reset, 2FA codes)")
        print(f"   • Test both IP-based and account-based rate limiting")
        print(f"   • Check for bypass techniques:")
        print(f"        - IP rotation (X-Forwarded-For header manipulation)")
        print(f"        - Username enumeration before brute-forcing")
        print(f"        - Timing attacks to identify valid accounts")
        print(f"   • Never exceed authorized testing limits")
        print(f"   • Document all findings with timestamps and request counts")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}LEGAL DISCLAIMER")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}  BRUTE-FORCE TESTING WITHOUT AUTHORIZATION IS ILLEGAL{Style.RESET_ALL}")
        print(f"   • Sending multiple authentication requests without permission = computer fraud")
        print(f"   • May violate Terms of Service and trigger criminal investigations")
        print(f"   • Even 'safe' testing may be considered unauthorized access")
        print(f"   • Always obtain WRITTEN authorization before ANY rate limit testing")
        print(f"   • Maintain detailed logs of authorized testing activities")
        print(f"   • Test ONLY on systems you own or have explicit written permission")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Rate limiting analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable or blocking requests.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")