import requests
import time
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style
import urllib3

urllib3.disable_warnings()
init(autoreset=True)



def is_directory_listing(response):
    """Accurate directory listing detection"""
    if response.status_code != 200:
        return False, None

    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return False, None

    html = response.text.lower()

    indicators = [
        "<title>index of",
        "<h1>index of",
        'href="../"',
        "parent directory",
    ]

    for indicator in indicators:
        if indicator in html:
            return True, indicator

    return False, None


def check_directory_listing(session, url):
    """HEAD → GET optimization"""
    try:
        head = session.head(url, timeout=6, verify=False, allow_redirects=True)

        if head.status_code not in [200, 403]:
            return False, head.status_code, None

        response = session.get(url, timeout=8, verify=False, allow_redirects=True)

        is_listing, indicator = is_directory_listing(response)
        return is_listing, response.status_code, indicator

    except requests.RequestException:
        return None, None, None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}        DIRECTORY LISTING SCANNER — PENTEST EDITION")
    print(f"{Fore.CYAN}{'=' * 70}\n")

    target = input(f"{Fore.YELLOW}Target URL (https://example.com): {Style.RESET_ALL}").strip()

    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        return

    session = requests.Session()

    print(f"\n{Fore.CYAN}[*] Checking common directories...{Style.RESET_ALL}")

    common_directories = [
    "/admin/", "/administrator/", "/panel/", "/dashboard/",
    "/backup/", "/backups/", "/old/", "/archive/", "/archives/",
    "/config/", "/configs/", "/conf/", "/settings/",
    "/uploads/", "/upload/", "/files/", "/file/", "/documents/",
    "/downloads/", "/download/",
    "/images/", "/img/", "/media/", "/static/", "/assets/",
    "/css/", "/js/", "/fonts/", "/vendor/", "/lib/", "/libs/",
    "/tmp/", "/temp/", "/cache/", "/logs/", "/log/", "/data/",
    "/includes/", "/inc/", "/core/", "/private/", "/secret/",
    "/storage/", "/public/", "/resources/",
    "/api/", "/v1/", "/v2/",
    "/test/", "/dev/", "/staging/", "/beta/",
    "/old-site/", "/new/", "/demo/",
    "/wp-content/", "/wp-content/uploads/", "/wp-includes/",
    "/node_modules/", "/dist/", "/build/",
]


    vulnerable_dirs = []

    for directory in common_directories:
        test_url = urljoin(target, directory)

        is_listing, status, indicator = check_directory_listing(session, test_url)

        if is_listing:
            vulnerable_dirs.append(test_url)
            print(f"{Fore.RED}[!] OPEN DIRECTORY → {test_url}{Style.RESET_ALL}")
            print(f"    Status: {status} | Indicator: {indicator}")

        elif is_listing is False:
            if status == 403:
                print(f"{Fore.GREEN}[✓] Forbidden → {test_url}{Style.RESET_ALL}")
            elif status == 404:
                print(f"{Fore.CYAN}[i] Not Found → {test_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] Protected → {test_url}{Style.RESET_ALL}")

        else:
            print(f"{Fore.YELLOW}[?] Error → {test_url}{Style.RESET_ALL}")

        time.sleep(0.15)


    print(f"\n{Fore.CYAN}[*] Checking sensitive files...{Style.RESET_ALL}")

    sensitive_paths = [
    "/.git/", "/.git/config", "/.git/HEAD",
    "/.svn/", "/.hg/",

    "/.env", "/.env.local", "/.env.dev", "/.env.prod", "/.env.production",
    "/config.php", "/config.json", "/config.yml", "/settings.py",
    "/web.config", "/app.config",

    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/database.sql",
    "/dump.sql", "/db.sql", "/site.sql",
    "/www.zip", "/site.zip", "/html.zip",

    "/error.log", "/debug.log", "/access.log", "/app.log",

    "/phpinfo.php", "/info.php", "/test.php",

    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.save",
    "/wp-content/debug.log",

    "/id_rsa", "/id_rsa.pub", "/.ssh/", "/.aws/credentials",

    "/.DS_Store", "/Thumbs.db",
    "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json",
    "/yarn.lock",

    "/index.php.bak", "/index.php.old", "/index.php.save",
    "/config.bak", "/config.old", "/config.save",

    "/server-status", "/server-info",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]


    exposed_files = []

    for path in sensitive_paths:
        test_url = urljoin(target, path)

        try:
            r = session.get(test_url, timeout=6, verify=False, allow_redirects=True)

            if r.status_code == 200:
                content_type = r.headers.get("Content-Type", "").lower()

                if "text/html" not in content_type:
                    exposed_files.append(test_url)
                    print(f"{Fore.MAGENTA}[!] EXPOSED FILE → {test_url}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[i] Accessible HTML → {test_url}{Style.RESET_ALL}")

            elif r.status_code == 403:
                print(f"{Fore.GREEN}[✓] Forbidden → {test_url}{Style.RESET_ALL}")

        except requests.RequestException:
            pass

        time.sleep(0.15)


    print(f"\n{Fore.CYAN}[*] Checking server headers...{Style.RESET_ALL}")

    try:
        r = session.get(target, timeout=8, verify=False)

        server = r.headers.get("Server", "Hidden")
        powered = r.headers.get("X-Powered-By", "Hidden")

        print(f"\nServer: {server}")
        print(f"X-Powered-By: {powered}")

        if server != "Hidden":
            print(f"{Fore.YELLOW}[!] Server version disclosure{Style.RESET_ALL}")

        if powered != "Hidden":
            print(f"{Fore.YELLOW}[!] Technology disclosure{Style.RESET_ALL}")

    except requests.RequestException:
        print(f"{Fore.YELLOW}[?] Could not retrieve headers{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}SCAN SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}")

    print(f"\nOpen directories: {Fore.RED}{len(vulnerable_dirs)}{Style.RESET_ALL}")
    print(f"Exposed sensitive files: {Fore.MAGENTA}{len(exposed_files)}{Style.RESET_ALL}")

    if vulnerable_dirs or exposed_files:
        print(f"\n{Fore.RED}[!] VULNERABILITIES DETECTED{Style.RESET_ALL}")

        for d in vulnerable_dirs:
            print(f"{Fore.RED}  • {d}{Style.RESET_ALL}")

        for f in exposed_files:
            print(f"{Fore.MAGENTA}  • {f}{Style.RESET_ALL}")

        print(f"\nRisk: MEDIUM → HIGH")
        print("Fix:")
        print("  • Disable directory listing (Apache Options -Indexes / Nginx autoindex off)")
        print("  • Restrict access to sensitive files")
        print("  • Move secrets outside web root")
        print("  • Harden permissions")

    else:
        print(f"{Fore.GREEN}[✓] No directory listing vulnerabilities found{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}Scan completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}\n")

