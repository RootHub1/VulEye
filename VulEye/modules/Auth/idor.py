import requests
import urllib.parse
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              IDOR VULNERABILITY TESTER                             {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL with parameters (e.g., http://site.com/user?id=123): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing URL parameters for IDOR vulnerability{Style.RESET_ALL}")

    parsed = urllib.parse.urlparse(target)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(
            f"\n{Fore.RED}[!] No URL parameters found. IDOR testing requires parameters like ?id=123{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[✓] Found parameters: {list(query_params.keys())}{Style.RESET_ALL}")

    idor_params = []
    for param, values in query_params.items():
        value = values[0]
        if value.isdigit():
            idor_params.append(param)
            print(f"{Fore.YELLOW}[!] Potential IDOR parameter: {param} = {value}{Style.RESET_ALL}")

    if not idor_params:
        print(
            f"\n{Fore.YELLOW}[!] No numeric parameters detected. IDOR typically requires numeric IDs.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}IDOR TESTING RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    original_value = query_params[idor_params[0]][0]
    original_id = int(original_value)

    test_cases = [
        original_id + 1,
        original_id - 1,
        original_id + 10,
        1,
        0
    ]

    for test_id in test_cases:
        test_params = query_params.copy()
        test_params[idor_params[0]] = [str(test_id)]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

        try:
            response = requests.get(test_url, timeout=10, verify=False)

            if response.status_code == 200:
                print(f"\n{Fore.YELLOW}[?] Parameter {idor_params[0]}={test_id} returned 200 OK{Style.RESET_ALL}")
                print(f"    URL: {test_url[:80]}...")

                if len(response.text) > 100:
                    snippet = response.text[:300]
                    print(f"    Response snippet: {snippet[:200]}...")

                sensitive_keywords = ['password', 'email', 'credit', 'ssn', 'address', 'phone']
                found_keywords = [kw for kw in sensitive_keywords if kw in response.text.lower()]

                if found_keywords:
                    print(f"{Fore.RED}[!] SENSITIVE DATA DETECTED: {', '.join(found_keywords)}{Style.RESET_ALL}")
                    vulnerable = True
            elif response.status_code == 403 or response.status_code == 401:
                print(
                    f"{Fore.GREEN}[✓] Parameter {idor_params[0]}={test_id} properly protected (Status: {response.status_code}){Style.RESET_ALL}")
            elif response.status_code == 404:
                print(
                    f"{Fore.CYAN}[i] Parameter {idor_params[0]}={test_id} not found (Status: {response.status_code}){Style.RESET_ALL}")
            else:
                print(
                    f"{Fore.YELLOW}[?] Parameter {idor_params[0]}={test_id} returned status {response.status_code}{Style.RESET_ALL}")

        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Timeout for {test_url[:60]}...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing {test_id}: {str(e)}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}IDOR TESTING COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"\n{Fore.RED}[!] POTENTIAL IDOR VULNERABILITY DETECTED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        print(f"   • Implement proper access control checks")
        print(f"   • Use indirect reference maps instead of direct object references")
        print(f"   • Validate user authorization for each request")
        print(f"   • Implement role-based access control (RBAC)")
    else:
        print(f"\n{Fore.GREEN}[✓] No obvious IDOR vulnerabilities detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Note:{Style.RESET_ALL}")
        print(f"   • This is a basic test. Manual verification recommended")
        print(f"   • Test with authenticated sessions")
        print(f"   • Check for UUID-based IDs (harder to enumerate)")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] IDOR analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")