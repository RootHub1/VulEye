import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              CSRF VULNERABILITY DETECTOR                          {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (login page or form endpoint): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing CSRF protections for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()
        response = session.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Found {len(forms)} form(s) on page{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CSRF PROTECTION ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        csrf_findings = []
        vulnerable_forms = 0
        protected_forms = 0

        csrf_indicators = [
            'csrf', 'token', 'authenticity_token', 'xsrf',
            '_token', 'anticsrf', 'nonce', 'verification'
        ]

        for i, form in enumerate(forms, 1):
            form_action = form.get('action', target)
            if not form_action.startswith(('http://', 'https://')):
                form_action = urllib.parse.urljoin(target, form_action)

            form_method = form.get('method', 'get').upper()
            inputs = form.find_all('input')

            has_csrf = False
            csrf_fields = []

            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(ind in name for ind in csrf_indicators):
                    has_csrf = True
                    csrf_fields.append(inp.get('name'))

            if has_csrf:
                protected_forms += 1
                status = f"{Fore.GREEN}[✓] PROTECTED{Style.RESET_ALL}"
                details = f"CSRF token field(s): {', '.join(csrf_fields)}"
            else:
                vulnerable_forms += 1
                status = f"{Fore.RED}[✗] VULNERABLE{Style.RESET_ALL}"
                details = "No CSRF token detected"
                csrf_findings.append({
                    'form_num': i,
                    'action': form_action,
                    'method': form_method,
                    'risk': 'HIGH'
                })

            print(f"\n{Fore.CYAN}Form #{i}{Style.RESET_ALL}")
            print(f"   Action: {form_action[:70]}")
            print(f"   Method: {form_method}")
            print(f"   Status: {status}")
            print(f"   Details: {details}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}COOKIE SECURITY ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        cookie_issues = []
        for cookie in session.cookies:
            name = cookie.name
            secure = cookie.secure
            httponly = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie._rest).lower()
            samesite = cookie.get_nonstandard_attr('SameSite', 'None')

            issues = []
            if not secure:
                issues.append("Missing Secure flag")
            if not httponly:
                issues.append("Missing HttpOnly flag")
            if samesite.lower() not in ['strict', 'lax']:
                issues.append(f"Weak SameSite ({samesite})")

            if issues:
                cookie_issues.append({'name': name, 'issues': issues})
                print(f"{Fore.YELLOW}[!] Cookie '{name}' issues:{Style.RESET_ALL}")
                for issue in issues:
                    print(f"    • {issue}")
            else:
                print(f"{Fore.GREEN}[✓] Cookie '{name}' properly configured{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Protected forms: {protected_forms}/{len(forms)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerable forms: {vulnerable_forms}/{len(forms)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Cookie issues: {len(cookie_issues)}{Style.RESET_ALL}")

        if vulnerable_forms > 0:
            print(f"\n{Fore.RED}[!] CSRF VULNERABILITIES DETECTED{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Risk Level: HIGH{Style.RESET_ALL}")
            print(f"   • Attackers can forge authenticated requests")
            print(f"   • Account takeover, data modification, or financial fraud possible")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Implement synchronizer token pattern:")
            print(f"        <input type='hidden' name='csrf_token' value='{{token}}'>")
            print(f"   • Use framework CSRF protection (Django, Laravel, Spring Security)")
            print(f"   • Set SameSite=Strict or Lax on all session cookies")
            print(f"   • Add double-submit cookie pattern as secondary defense")
            print(f"   • Verify Origin/Referer headers for critical actions")
            print(f"   • Use CAPTCHA for sensitive operations (password change, payments)")
        else:
            print(f"\n{Fore.GREEN}[✓] No CSRF vulnerabilities detected in forms{Style.RESET_ALL}")
            if cookie_issues:
                print(f"\n{Fore.YELLOW}[!] Cookie security improvements recommended:{Style.RESET_ALL}")
                print(f"   • Set Secure flag on all cookies")
                print(f"   • Set HttpOnly flag on session cookies")
                print(f"   • Set SameSite=Strict or Lax")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] CSRF analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}⚠️  IMPORTANT:{Style.RESET_ALL}")
        print(f"   This is a static analysis. Dynamic testing with authenticated sessions")
        print(f"   and JavaScript-rendered forms may reveal additional vulnerabilities.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")