import requests
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style

init(autoreset=True)


def check_directory_listing(url):
    try:
        response = requests.get(url, timeout=8, verify=False)

        if response.status_code != 200:
            return False, response.status_code, None

        content = response.text.lower()

        index_indicators = [
            'index of /', 'directory listing', 'parent directory',
            '<title>directory', '<h1>index of', 'last modified',
            '[dirs]', '[files]', 'table class="fancy"'
        ]

        for indicator in index_indicators:
            if indicator in content:
                return True, response.status_code, indicator

        return False, response.status_code, None
    except:
        return None, None, None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              DIRECTORY LISTING CHECKER                            {Fore.CYAN}║")
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

    print(f"\n{Fore.CYAN}[+] Checking for directory listing vulnerabilities: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}COMMON DIRECTORY PATHS CHECK")
        print(f"{Fore.YELLOW}Note: Testing 20 common paths for open directory listing{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        common_directories = [
            '/admin/',
            '/backup/',
            '/Config/',
            '/uploads/',
            '/images/',
            '/files/',
            '/downloads/',
            '/documents/',
            '/assets/',
            '/static/',
            '/tmp/',
            '/temp/',
            '/logs/',
            '/data/',
            '/includes/',
            '/lib/',
            '/css/',
            '/js/',
            '/vendor/',
            '/wp-content/uploads/'
        ]

        vulnerable_dirs = []
        total_tested = 0

        for directory in common_directories:
            total_tested += 1
            test_url = urljoin(target, directory)

            is_listing, status, indicator = check_directory_listing(test_url)

            if is_listing:
                vulnerable_dirs.append({
                    'url': test_url,
                    'status': status,
                    'indicator': indicator
                })
                print(f"{Fore.RED}[!] OPEN DIRECTORY: {test_url}{Style.RESET_ALL}")
                print(f"    Status: {status} | Indicator: {indicator}")
            elif is_listing is False:
                if status == 200:
                    print(f"{Fore.GREEN}[✓] Protected: {test_url} (Status: {status}){Style.RESET_ALL}")
                elif status == 403:
                    print(f"{Fore.GREEN}[✓] Forbidden: {test_url} (Status: {status}){Style.RESET_ALL}")
                elif status == 404:
                    print(f"{Fore.CYAN}[i] Not found: {test_url} (Status: {status}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[?] Error checking: {test_url}{Style.RESET_ALL}")

            import time
            time.sleep(0.3)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SENSITIVE PATH CHECK")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        sensitive_paths = [
            '/.git/',
            '/.svn/',
            '/.hg/',
            '/.env',
            '/backup.zip',
            '/database.sql',
            '/Config.php',
            '/wp-Config.php',
            '/phpinfo.php',
            '/debug.log'
        ]

        exposed_files = []

        for path in sensitive_paths:
            test_url = urljoin(target, path)

            try:
                response = requests.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    if 'html' not in response.headers.get('Content-Type', '').lower():
                        exposed_files.append(test_url)
                        print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] EXPOSED FILE: {test_url}{Style.RESET_ALL}")
                        print(
                            f"    Status: {response.status_code} | Content-Type: {response.headers.get('Content-Type', 'unknown')}")
                    else:
                        print(f"{Fore.YELLOW}[i] Accessible: {test_url} (HTML content){Style.RESET_ALL}")
                elif response.status_code == 403:
                    print(f"{Fore.GREEN}[✓] Protected: {test_url} (Status: {response.status_code}){Style.RESET_ALL}")

            except:
                pass

            time.sleep(0.3)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RESULTS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Total directories tested: {total_tested}{Style.RESET_ALL}")
        print(f"{Fore.RED}Open directories found: {len(vulnerable_dirs)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Exposed sensitive files: {len(exposed_files)}{Style.RESET_ALL}")

        if vulnerable_dirs or exposed_files:
            print(f"\n{Fore.RED}[!] DIRECTORY LISTING VULNERABILITIES DETECTED{Style.RESET_ALL}")

            if vulnerable_dirs:
                print(f"\n{Fore.YELLOW} Open Directories:{Style.RESET_ALL}")
                for item in vulnerable_dirs:
                    print(f"\n{Fore.RED}• {item['url']}{Style.RESET_ALL}")
                    print(f"  Status: {item['status']} | Indexing detected via: {item['indicator']}")

            if exposed_files:
                print(f"\n{Fore.MAGENTA} Exposed Sensitive Files:{Style.RESET_ALL}")
                for file_url in exposed_files:
                    print(f"  • {file_url}")

            print(f"\n{Fore.YELLOW}Risk Level: MEDIUM to HIGH{Style.RESET_ALL}")
            print(f"   • Information disclosure - attackers can map file structure")
            print(f"   • Sensitive files may be directly accessible")
            print(f"   • Source code, configs, backups exposed")
            print(f"   • Facilitates further attacks (LFI, path traversal)")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Disable directory listing in web server configuration:")
            print(f"        Apache: Options -Indexes")
            print(f"        Nginx: autoindex off;")
            print(f"        IIS: Remove 'Directory Browsing' feature")
            print(f"   • Create empty index.html/index.php files in sensitive directories")
            print(f"   • Block access to sensitive paths via .htaccess or web.Config:")
            print(f"        <FilesMatch \"\\.(git|env|sql|log|bak)$\">")
            print(f"            Deny from all")
            print(f"        </FilesMatch>")
            print(f"   • Move sensitive files outside web root directory")
            print(f"   • Implement proper file permissions (no world-readable configs)")
            print(f"   • Use robots.txt to discourage crawling (not security control)")
            print(f"   • Monitor access logs for directory enumeration attempts")
        else:
            print(f"\n{Fore.GREEN}[✓] No open directory listings detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue monitoring for new exposed directories")
            print(f"   • Regularly audit web server configuration")
            print(f"   • Use security headers (X-Content-Type-Options: nosniff)")
            print(f"   • Implement proper access controls for all directories")
            print(f"   • Remove unnecessary files and directories from production")
            print(f"   • Use automated scanning tools for continuous monitoring")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Checking server configuration headers...{Style.RESET_ALL}")

        try:
            response = session.get(target, timeout=8, verify=False)

            server = response.headers.get('Server', 'Not disclosed')
            x_powered_by = response.headers.get('X-Powered-By', 'Not disclosed')

            print(f"\n{Fore.CYAN}Server Information:{Style.RESET_ALL}")
            print(f"   Server: {server}")
            print(f"   X-Powered-By: {x_powered_by}")

            if server != 'Not disclosed':
                print(f"   {Fore.YELLOW}  Server version disclosed - consider hiding{Style.RESET_ALL}")

            if x_powered_by != 'Not disclosed':
                print(f"   {Fore.YELLOW}  Technology stack disclosed - consider removing header{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.YELLOW}[?] Could not retrieve server headers: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Directory listing analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL REMINDER:{Style.RESET_ALL}")
        print(f"   Directory enumeration without authorization may violate laws.")
        print(f"   Always obtain written permission before testing any system.")
        print(f"   Document all authorized testing activities for legal protection.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")