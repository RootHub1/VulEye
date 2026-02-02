import requests
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              EXPOSED FILES SCANNER                                 {Fore.CYAN}║")
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

    if target.endswith('/'):
        target = target[:-1]

    print(f"\n{Fore.CYAN}[+] Scanning for exposed sensitive files: {target}{Style.RESET_ALL}")

    sensitive_paths = [
        '.git/config',
        '.git/HEAD',
        '.env',
        '.env.backup',
        '.env.local',
        'backup.zip',
        'backup.tar.gz',
        'backup.sql',
        'database.sql',
        'dump.sql',
        'wp-config.php',
        'wp-config.php.backup',
        'wp-config.php~',
        'config.php',
        'config.inc.php',
        'config.ini',
        'config.json',
        'phpinfo.php',
        'info.php',
        'robots.txt',
        '.htaccess',
        '.htpasswd',
        '.DS_Store',
        'web.config',
        'web.xml',
        'composer.json',
        'composer.lock',
        'package.json',
        'package-lock.json',
        'yarn.lock',
        'admin/',
        'adminer.php',
        'phpmyadmin/',
        'pma/',
        'dbadmin/',
        'mysql/',
        'sql/',
        'debug.log',
        'error.log',
        'access.log',
        'logs/',
        'core/',
        'uploads/',
        'backups/',
        'temp/',
        'tmp/',
        'cache/',
        'install.php',
        'setup.php',
        'readme.html',
        'CHANGELOG',
        'LICENSE',
        'TODO',
        'api/',
        'swagger.json',
        'swagger.yaml',
        '.gitignore',
        '.svn/entries',
        '.hg/hgrc',
        'CVS/Root',
        'Thumbs.db'
    ]

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SCAN RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    exposed_files = []
    total_scanned = 0
    errors = 0

    for path in sensitive_paths:
        total_scanned += 1
        test_url = f"{target}/{path}"

        try:
            response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', 'unknown')
                content_preview = response.text[:200] if response.text else ''

                if 'html' in content_type.lower() and len(response.text) < 100:
                    continue

                exposed_files.append((path, response.status_code, content_type))
                print(f"{Fore.RED}[!] EXPOSED: {path}{Style.RESET_ALL}")
                print(f"    URL: {test_url}")
                print(f"    Status: {response.status_code} | Content-Type: {content_type}")

                if path == '.git/config':
                    print(f"    {Fore.RED}CRITICAL: Git repository exposed - source code leakage risk{Style.RESET_ALL}")
                elif path == '.env':
                    print(
                        f"    {Fore.RED}CRITICAL: Environment variables exposed - credentials leakage risk{Style.RESET_ALL}")
                elif 'backup' in path.lower() or 'sql' in path.lower():
                    print(f"    {Fore.RED}CRITICAL: Database backup exposed - data breach risk{Style.RESET_ALL}")
                elif 'config' in path.lower() and ('php' in path or 'json' in path):
                    print(f"    {Fore.RED}CRITICAL: Configuration file exposed - secrets leakage risk{Style.RESET_ALL}")

                if content_preview:
                    preview_lines = [line.strip() for line in content_preview.split('\n') if line.strip()][:3]
                    if preview_lines:
                        print(f"    Preview: {preview_lines[0][:100]}...")

            elif response.status_code == 403:
                print(f"{Fore.YELLOW}[i] Forbidden: {path} (Status: 403){Style.RESET_ALL}")

        except requests.exceptions.Timeout:
            errors += 1
        except requests.exceptions.ConnectionError:
            errors += 1
        except Exception:
            errors += 1

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Total paths scanned: {total_scanned}{Style.RESET_ALL}")
    print(f"{Fore.RED}Exposed files found: {len(exposed_files)}{Style.RESET_ALL}")
    if errors > 0:
        print(f"{Fore.YELLOW}Errors/Timeouts: {errors}{Style.RESET_ALL}")

    if exposed_files:
        print(f"\n{Fore.RED}[!] SECURITY RISKS DETECTED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Critical Risks:{Style.RESET_ALL}")
        for path, status, content_type in exposed_files:
            if '.git' in path:
                print(f"   • Git repository exposed at /{path}")
            elif '.env' in path:
                print(f"   • Environment variables exposed at /{path}")
            elif 'backup' in path.lower() or 'sql' in path.lower():
                print(f"   • Database backup exposed at /{path}")
            elif 'config' in path.lower() and ('php' in path or 'json' in path or 'ini' in path):
                print(f"   • Configuration file exposed at /{path}")

        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        print(f"   • Remove sensitive files from web root immediately")
        print(f"   • Block access via .htaccess or web server configuration:")
        print(f"        <FilesMatch \"\\.(env|git|sql|log|bak)$\">")
        print(f"            Deny from all")
        print(f"        </FilesMatch>")
        print(f"   • Use proper backup storage outside web root")
        print(f"   • Implement security headers (Content-Security-Policy)")
        print(f"   • Regularly scan for exposed files during security audits")
    else:
        print(f"\n{Fore.GREEN}[✓] No obviously exposed sensitive files detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Note:{Style.RESET_ALL}")
        print(f"   • This scan checks common paths only")
        print(f"   • Manual review recommended for custom application paths")
        print(f"   • Check server configuration for directory listing protection")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Exposed files scan completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")