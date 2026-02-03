import requests
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style

init(autoreset=True)


def get_default_credentials(device_type):
    credentials = {
        'router': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'admin'),
            ('admin', '1234')
        ],
        'web_admin': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('admin', '')
        ],
        'camera': [
            ('admin', '12345'),
            ('admin', '123456'),
            ('admin', ''),
            ('root', 'root'),
            ('admin', 'admin')
        ],
        'wordpress': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('administrator', 'password')
        ],
        'joomla': [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('administrator', 'password')
        ]
    }
    return credentials.get(device_type, credentials['web_admin'])


def test_login(url, username, password):
    try:
        data = {
            'username': username,
            'user': username,
            'login': username,
            'email': username,
            'password': password,
            'pass': password,
            'passwd': password
        }

        response = requests.post(url, data=data, timeout=8, verify=False, allow_redirects=False)

        failed_indicators = [
            'invalid', 'error', 'failed', 'incorrect', 'wrong', 'denied',
            'username or password', 'login failed', 'auth failed'
        ]

        if response.status_code in [301, 302, 303, 307, 308]:
            return True

        if response.status_code == 200:
            text = response.text.lower()
            if not any(ind in text for ind in failed_indicators):
                if len(response.text) > 1000:
                    return True

        return False
    except:
        return None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              DEFAULT CREDENTIALS CHECKER                          {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL (login page, e.g., http://192.168.1.1/login.php): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing target: {target}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}DEVICE TYPE SELECTION")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"   1. Router / Network Device")
    print(f"   2. Web Admin Interface (Generic)")
    print(f"   3. IP Camera / DVR")
    print(f"   4. WordPress Admin")
    print(f"   5. Joomla Admin")
    print(f"   0. Custom (test generic credentials)")

    choice = input(f"\n{Fore.YELLOW}Select device type [0-5]: {Style.RESET_ALL}").strip()

    device_types = {
        '1': 'router',
        '2': 'web_admin',
        '3': 'camera',
        '4': 'wordpress',
        '5': 'joomla',
        '0': 'web_admin'
    }

    device_type = device_types.get(choice, 'web_admin')
    credentials = get_default_credentials(device_type)

    print(f"\n{Fore.CYAN}[+] Testing {len(credentials)} common default credential combinations{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Limited to 5 attempts to avoid lockouts and detection{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}DEFAULT CREDENTIAL TESTING")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerable = False
    tested = 0

    for username, password in credentials[:5]:
        tested += 1
        print(f"\n{Fore.CYAN}[→] Attempt {tested}/5: {username}:{password if password else '(empty)'}{Style.RESET_ALL}")

        result = test_login(target, username, password)

        if result is True:
            vulnerable = True
            print(
                f"{Fore.MAGENTA}{Style.BRIGHT}[!] DEFAULT CREDENTIALS WORK: {username}:{password if password else '(empty)'}{Style.RESET_ALL}")
            print(f"    {Fore.RED}  CRITICAL: Device accessible with default credentials!{Style.RESET_ALL}")
            break
        elif result is False:
            print(f"{Fore.GREEN}[✓] Rejected: Invalid credentials{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[?] Unknown response (timeout/connection error){Style.RESET_ALL}")

        import time
        time.sleep(1.5)

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RESULTS SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerable:
        print(
            f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL VULNERABILITY: Default Credentials Accepted{Style.RESET_ALL}")
        print(f"\n{Fore.RED}Risk Level: CRITICAL{Style.RESET_ALL}")
        print(f"   • Full administrative access possible")
        print(f"   • Complete device compromise")
        print(f"   • Network pivot point for lateral movement")
        print(f"   • Data theft, configuration changes, firmware replacement")

        print(f"\n{Fore.YELLOW}Immediate Actions Required:{Style.RESET_ALL}")
        print(f"   1. CHANGE DEFAULT PASSWORD IMMEDIATELY")
        print(f"   2. Create strong unique password (12+ chars, mix case/numbers/symbols)")
        print(f"   3. Disable default accounts if possible")
        print(f"   4. Update firmware to latest version")
        print(f"   5. Restrict admin interface to trusted networks only")
        print(f"   6. Enable 2FA if supported")
        print(f"   7. Monitor logs for unauthorized access attempts")

        print(f"\n{Fore.CYAN}Common Default Credentials Database:{Style.RESET_ALL}")
        print(f"   • Router default passwords: https://cirt.net/passwords")
        print(f"   • IoT device defaults: https://www.defaultpassword.com")
        print(f"   • CVE-2017-17215 (Huawei router backdoor)")
        print(f"   • CVE-2020-8515 (DrayTek router credential leak)")
    else:
        print(f"\n{Fore.GREEN}[✓] No default credentials accepted (tested {tested} combinations){Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Important Notes:{Style.RESET_ALL}")
        print(f"   • This test checked only TOP 5 most common combinations")
        print(f"   • Many devices have vendor-specific defaults not tested here")
        print(f"   • Always change defaults BEFORE connecting device to network")
        print(f"   • Use password manager to generate/store unique passwords")
        print(f"   • For comprehensive testing, consult vendor documentation")

        print(f"\n{Fore.YELLOW}Security Best Practices:{Style.RESET_ALL}")
        print(f"   • Change ALL default credentials before deployment")
        print(f"   • Use password manager for unique strong passwords")
        print(f"   • Disable remote admin access when not needed")
        print(f"   • Segment IoT devices on separate VLAN")
        print(f"   • Regularly update firmware")
        print(f"   • Monitor for unusual login attempts")
        print(f"   • Maintain inventory of all network devices and credentials")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}LEGAL & ETHICAL GUIDANCE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.RED}  CRITICAL LEGAL WARNING:{Style.RESET_ALL}")
    print(f"   • Testing default credentials on devices you don't own = illegal")
    print(f"   • Even 'harmless' login attempts may violate computer fraud laws")
    print(f"   • Always obtain WRITTEN authorization before testing ANY system")
    print(f"   • Document all authorized testing activities")
    print(f"   • Never test devices on networks you don't control")
    print(f"\n{Fore.GREEN} Responsible Disclosure:{Style.RESET_ALL}")
    print(f"   If you discover default credentials on someone else's device:")
    print(f"   1. DO NOT log in or access the device")
    print(f"   2. Contact owner/network administrator immediately")
    print(f"   3. Provide details privately (not publicly)")
    print(f"   4. Allow reasonable time for remediation before public disclosure")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Default credentials check completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")