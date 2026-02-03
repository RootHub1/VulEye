import socket
import requests
import threading
from queue import Queue
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SUBDOMAIN ENUMERATOR                                  {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    domain = input(f"\n{Fore.YELLOW}Enter target domain (e.g., example.com): {Style.RESET_ALL}").strip()

    if not domain:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://')[1].split('/')[0]

    print(f"\n{Fore.CYAN}[+] Starting subdomain enumeration for: {domain}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Using built-in wordlist (common subdomains){Style.RESET_ALL}")

    subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'imap',
        'ns1', 'ns2', 'test', 'dev', 'staging', 'admin', 'secure', 'vpn',
        'shop', 'api', 'blog', 'forum', 'support', 'portal', 'app', 'beta',
        'cdn', 'static', 'img', 'images', 'media', 'm', 'mobile', 'docs',
        'help', 'wiki', 'status', 'server', 'db', 'sql', 'direct', 'cpanel',
        'webdisk', 'autodiscover', 'autoconfig', 'login', 'auth', 'sso'
    ]

    found = []
    lock = threading.Lock()
    q = Queue()

    for sub in subdomains:
        q.put(sub)

    def check_subdomain():
        while not q.empty():
            sub = q.get()
            target = f"{sub}.{domain}"

            try:
                ip = socket.gethostbyname(target)
                try:
                    url = f"http://{target}"
                    resp = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                    status = resp.status_code
                    title = "N/A"
                    if resp.status_code == 200:
                        title_match = __import__('re').search(r'<title>(.*?)</title>', resp.text,
                                                              __import__('re').IGNORECASE)
                        if title_match:
                            title = title_match.group(1)[:50]

                    with lock:
                        found.append((sub, ip, status, title))
                        print(f"{Fore.GREEN}[✓] FOUND: {target} → {ip} (HTTP {status}){Style.RESET_ALL}")
                        if title != "N/A":
                            print(f"    Title: {title}")
                except:
                    with lock:
                        found.append((sub, ip, "N/A", "N/A"))
                        print(f"{Fore.YELLOW}[i] DNS only: {target} → {ip}{Style.RESET_ALL}")
            except socket.gaierror:
                pass
            except Exception:
                pass
            finally:
                q.task_done()

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}ENUMERATION IN PROGRESS (checking {len(subdomains)} subdomains){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    threads = []
    for _ in range(20):
        t = threading.Thread(target=check_subdomain, daemon=True)
        t.start()
        threads.append(t)

    q.join()

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RESULTS SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if found:
        print(f"\n{Fore.GREEN}[✓] Found {len(found)} active subdomain(s):{Style.RESET_ALL}")
        for sub, ip, status, title in sorted(found):
            print(f"   {Fore.CYAN}• {sub}.{domain}{Style.RESET_ALL}")
            print(f"     IP: {ip} | HTTP: {status}")
            if title != "N/A":
                print(f"     Title: {title}")

        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        print(f"   • Verify ownership of all discovered subdomains")
        print(f"   • Check for exposed services (admin panels, APIs)")
        print(f"   • Scan discovered subdomains with other VulEye modules")
        print(f"   • Monitor for unauthorized subdomain creation")
        print(f"   • Implement DNS monitoring and alerts")
    else:
        print(f"\n{Fore.YELLOW}[!] No active subdomains discovered{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Note:{Style.RESET_ALL}")
        print(f"   • This scan used a limited built-in wordlist")
        print(f"   • For comprehensive results:")
        print(f"        - Use larger wordlists (e.g., seclists/Discovery/DNS)")
        print(f"        - Integrate with certificate transparency logs")
        print(f"        - Use dedicated tools: amass, sublist3r, assetfinder")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Subdomain enumeration completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}⚠️  LEGAL REMINDER:{Style.RESET_ALL}")
    print(f"   All discovered assets must be authorized for testing.")
    print(f"   Unauthorized scanning of discovered subdomains = illegal activity.")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")