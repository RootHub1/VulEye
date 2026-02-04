import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def analyze_cookie(cookie, domain):
    issues = []
    warnings = []

    name = cookie.name
    value = cookie.value
    secure = cookie.secure
    httponly = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie._rest).lower()
    samesite = cookie.get_nonstandard_attr('SameSite', 'None')
    domain_attr = cookie.domain
    path = cookie.path

    if not secure:
        issues.append({
            'severity': 'HIGH',
            'issue': 'Missing Secure Flag',
            'description': f'Cookie "{name}" can be transmitted over unencrypted HTTP',
            'impact': 'Session hijacking via MITM attacks',
            'fix': 'Set Secure flag: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
        })

    if not httponly:
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'Missing HttpOnly Flag',
            'description': f'Cookie "{name}" accessible via JavaScript',
            'impact': 'XSS attacks can steal cookie values',
            'fix': 'Set HttpOnly flag: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
        })

    if samesite.lower() not in ['strict', 'lax']:
        if samesite.lower() == 'none':
            if not secure:
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'SameSite=None without Secure flag',
                    'description': f'Cookie "{name}" allows cross-site requests without HTTPS',
                    'impact': 'CSRF attacks possible',
                    'fix': 'SameSite=None requires Secure flag'
                })
            else:
                warnings.append({
                    'issue': 'SameSite=None (Cross-site allowed)',
                    'description': f'Cookie "{name}" allows cross-site requests',
                    'recommendation': 'Use SameSite=Lax or Strict unless cross-site functionality required'
                })
        else:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Missing or Weak SameSite Attribute',
                'description': f'Cookie "{name}" has SameSite={samesite}',
                'impact': 'CSRF attacks possible',
                'fix': 'Set SameSite=Strict or Lax: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict'
            })

    if domain_attr and domain not in domain_attr:
        warnings.append({
            'issue': 'Domain Mismatch',
            'description': f'Cookie domain "{domain_attr}" does not match target domain "{domain}"',
            'recommendation': 'Ensure cookie domain matches or is subdomain of target'
        })

    if not path or path == '/':
        warnings.append({
            'issue': 'Broad Path Scope',
            'description': f'Cookie "{name}" accessible on all paths',
            'recommendation': 'Restrict cookie to specific path: Path=/admin'
        })

    sensitive_keywords = ['session', 'auth', 'token', 'jwt', 'password', 'secret']
    if any(keyword in name.lower() for keyword in sensitive_keywords):
        if not secure or not httponly:
            issues.append({
                'severity': 'CRITICAL',
                'issue': 'Sensitive Cookie Missing Security Flags',
                'description': f'Sensitive cookie "{name}" lacks proper security attributes',
                'impact': 'High risk of session hijacking and credential theft',
                'fix': 'Set all security flags: Secure; HttpOnly; SameSite=Strict'
            })

    return issues, warnings


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              COOKIE SECURITY CHECKER                              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing cookie security for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()
        response = session.get(target, timeout=10, verify=False)
        cookies = session.cookies
        domain = urlparse(target).netloc

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}COOKIE SECURITY ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if not cookies:
            print(f"\n{Fore.YELLOW}[!] No cookies set by the server.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] This may indicate:{Style.RESET_ALL}")
            print(f"   • Session management not yet initialized")
            print(f"   • Cookies set only after authentication")
            print(f"   • Application uses alternative session mechanisms (JWT in headers)")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[✓] Found {len(cookies)} cookie(s):{Style.RESET_ALL}")

        all_issues = []
        all_warnings = []

        for cookie in cookies:
            name = cookie.name
            value = cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value
            print(f"\n{Fore.CYAN}Cookie: {name}{Style.RESET_ALL}")
            print(f"   Value: {value}")
            print(f"   Domain: {cookie.domain or 'Not set'}")
            print(f"   Path: {cookie.path or '/'}")

            issues, warnings = analyze_cookie(cookie, domain)

            for issue in issues:
                all_issues.append((name, issue))
                severity_color = Fore.MAGENTA if issue['severity'] == 'CRITICAL' else (
                    Fore.RED if issue['severity'] == 'HIGH' else Fore.YELLOW)
                print(f"\n{severity_color}   • {issue['issue']} ({issue['severity']}){Style.RESET_ALL}")
                print(f"     {issue['description']}")

            for warning in warnings:
                all_warnings.append((name, warning))
                print(f"\n{Fore.YELLOW}     {warning['issue']}{Style.RESET_ALL}")
                print(f"     {warning['description']}")

            if not issues and not warnings:
                print(f"\n{Fore.GREEN}   ✓ No security issues detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        critical_count = sum(1 for _, issue in all_issues if issue['severity'] == 'CRITICAL')
        high_count = sum(1 for _, issue in all_issues if issue['severity'] == 'HIGH')
        medium_count = sum(1 for _, issue in all_issues if issue['severity'] == 'MEDIUM')

        print(f"\n{Fore.GREEN}Total cookies analyzed: {len(cookies)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Critical issues: {critical_count}{Style.RESET_ALL}")
        print(f"{Fore.RED}High severity issues: {high_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium severity issues: {medium_count}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Warnings: {len(all_warnings)}{Style.RESET_ALL}")

        if all_issues:
            print(f"\n{Fore.RED}[!] COOKIE SECURITY ISSUES DETECTED{Style.RESET_ALL}")

            print(f"\n{Fore.MAGENTA} Critical & High Severity Issues:{Style.RESET_ALL}")
            for cookie_name, issue in all_issues:
                if issue['severity'] in ['CRITICAL', 'HIGH']:
                    severity_color = Fore.MAGENTA if issue['severity'] == 'CRITICAL' else Fore.RED
                    print(f"\n{severity_color}• {cookie_name}: {issue['issue']} ({issue['severity']}){Style.RESET_ALL}")
                    print(f"  Description: {issue['description']}")
                    print(f"  Impact: {issue['impact']}")
                    print(f"  Fix: {issue['fix']}")

            print(f"\n{Fore.YELLOW}Medium Severity Issues:{Style.RESET_ALL}")
            for cookie_name, issue in all_issues:
                if issue['severity'] == 'MEDIUM':
                    print(f"\n{Fore.YELLOW}• {cookie_name}: {issue['issue']}{Style.RESET_ALL}")
                    print(f"  Description: {issue['description']}")
                    print(f"  Impact: {issue['impact']}")
                    print(f"  Fix: {issue['fix']}")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Set Secure flag on ALL cookies containing sensitive data")
            print(f"   • Set HttpOnly flag on session/authentication cookies")
            print(f"   • Use SameSite=Strict or Lax to prevent CSRF attacks")
            print(f"   • Implement proper session management:")
            print(f"        - Use strong random session IDs")
            print(f"        - Implement session timeout (15-30 minutes)")
            print(f"        - Regenerate session ID after login")
            print(f"        - Implement session invalidation on logout")
            print(f"   • For sensitive applications:")
            print(f"        - Use additional authentication factors")
            print(f"        - Implement IP binding for sessions")
            print(f"        - Monitor for session hijacking attempts")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical cookie security issues detected{Style.RESET_ALL}")

            if all_warnings:
                print(f"\n{Fore.CYAN}[i] Recommendations for improvement:{Style.RESET_ALL}")
                for cookie_name, warning in all_warnings:
                    print(f"\n{Fore.CYAN}• {cookie_name}: {warning['issue']}{Style.RESET_ALL}")
                    print(f"  {warning['description']}")
                    print(f"  Recommendation: {warning['recommendation']}")

            print(f"\n{Fore.GREEN}[✓] Cookie security appears properly configured{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue monitoring cookie attributes")
            print(f"   • Regularly audit session management")
            print(f"   • Implement Content Security Policy (CSP)")
            print(f"   • Use HSTS header for HTTPS enforcement")
            print(f"   • Consider implementing cookie prefixes:")
            print(f"        - __Host- for same-origin, Secure, Path=/ cookies")
            print(f"        - __Secure- for Secure cookies")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Checking for common session vulnerabilities...{Style.RESET_ALL}")

        session_issues = []

        for cookie in cookies:
            name = cookie.name.lower()
            value = cookie.value

            if 'session' in name or 'sess' in name:
                if len(value) < 16:
                    session_issues.append({
                        'issue': 'Weak Session ID Length',
                        'description': f'Session cookie "{cookie.name}" value is only {len(value)} characters',
                        'recommendation': 'Use minimum 32-character random session IDs'
                    })

                if value.isdigit() or value.isalpha():
                    session_issues.append({
                        'issue': 'Predictable Session ID',
                        'description': f'Session cookie "{cookie.name}" appears sequential or non-random',
                        'recommendation': 'Use cryptographically secure random values'
                    })

        if session_issues:
            print(f"\n{Fore.YELLOW}[!] Session Management Issues:{Style.RESET_ALL}")
            for issue in session_issues:
                print(f"\n{Fore.YELLOW}• {issue['issue']}{Style.RESET_ALL}")
                print(f"  {issue['description']}")
                print(f"  Recommendation: {issue['recommendation']}")
        else:
            print(f"\n{Fore.GREEN}[✓] No obvious session management issues detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Cookie security analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL REMINDER:{Style.RESET_ALL}")
        print(f"   Cookie analysis may involve examining session data.")
        print(f"   Always obtain written permission before testing authentication systems.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")