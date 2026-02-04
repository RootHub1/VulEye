import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def generate_test_page(target_url, output_file="clickjacking_test.html"):
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test Page</title>
    <style>
        body {{ margin: 0; padding: 0; overflow: hidden; }}
        #decoy {{ 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%); 
            font-family: Arial, sans-serif; 
            font-size: 24px; 
            color: white; 
            background: rgba(220, 53, 69, 0.9); 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center; 
            z-index: 100; 
        }}
        #target-frame {{ 
            position: absolute; 
            top: 0; 
            left: 0; 
            width: 100%; 
            height: 100%; 
            opacity: 0.8; 
            z-index: 1; 
        }}
    </style>
</head>
<body>
    <div id="decoy">
        <h2>🎉 FREE GIFT CARD! 🎉</h2>
        <p>Click here to claim your $1000 Amazon gift card!</p>
        <button style="padding: 15px 30px; font-size: 18px; background: #ffc107; border: none; border-radius: 5px; cursor: pointer;">
            CLAIM NOW
        </button>
    </div>
    <iframe id="target-frame" src="{target_url}"></iframe>
</body>
</html>"""

    with open(output_file, 'w') as f:
        f.write(html_content)
    return output_file


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              CLICKJACKING VULNERABILITY TESTER                    {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL to test (e.g., https://example.com/login): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing frame protection headers for: {target}{Style.RESET_ALL}")

    try:
        response = requests.get(target, timeout=10, verify=False)
        headers = response.headers

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}FRAME PROTECTION HEADER ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        x_frame = headers.get('X-Frame-Options', 'NOT SET')
        csp = headers.get('Content-Security-Policy', '')

        frame_ancestors = 'NOT FOUND'
        if csp:
            for directive in csp.split(';'):
                if 'frame-ancestors' in directive.lower():
                    frame_ancestors = directive.strip()
                    break

        print(f"\n{Fore.CYAN}X-Frame-Options:{Style.RESET_ALL} {x_frame}")
        print(f"{Fore.CYAN}Content-Security-Policy (frame-ancestors):{Style.RESET_ALL} {frame_ancestors}")

        vulnerable = False
        protection_level = "NONE"

        if x_frame != 'NOT SET':
            x_frame = x_frame.upper()
            if x_frame in ['DENY', 'SAMEORIGIN']:
                protection_level = "GOOD"
                print(f"\n{Fore.GREEN}[✓] X-Frame-Options properly configured: {x_frame}{Style.RESET_ALL}")
            elif 'ALLOW-FROM' in x_frame:
                protection_level = "PARTIAL"
                print(f"\n{Fore.YELLOW}[!] X-Frame-Options uses deprecated ALLOW-FROM directive{Style.RESET_ALL}")
            else:
                protection_level = "WEAK"
                print(f"\n{Fore.YELLOW}[!] X-Frame-Options has unrecognized value: {x_frame}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[✗] X-Frame-Options header MISSING{Style.RESET_ALL}")
            vulnerable = True

        if frame_ancestors != 'NOT FOUND':
            if 'frame-ancestors' in frame_ancestors.lower():
                if "'none'" in frame_ancestors.lower():
                    protection_level = "GOOD"
                    print(
                        f"{Fore.GREEN}[✓] CSP frame-ancestors properly configured: {frame_ancestors}{Style.RESET_ALL}")
                elif "'self'" in frame_ancestors.lower() or 'https://' in frame_ancestors.lower():
                    protection_level = "GOOD"
                    print(
                        f"{Fore.GREEN}[✓] CSP frame-ancestors properly configured: {frame_ancestors}{Style.RESET_ALL}")
                else:
                    protection_level = "PARTIAL"
                    print(
                        f"{Fore.YELLOW}[!] CSP frame-ancestors has weak configuration: {frame_ancestors}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] CSP header found but no frame-ancestors directive{Style.RESET_ALL}")
        else:
            if x_frame == 'NOT SET':
                print(f"{Fore.RED}[✗] Content-Security-Policy frame-ancestors MISSING{Style.RESET_ALL}")
                vulnerable = True
            else:
                print(f"{Fore.YELLOW}[i] CSP frame-ancestors not present (relying on X-Frame-Options){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CLICKJACKING TEST PAGE GENERATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        test_file = generate_test_page(target)
        print(f"\n{Fore.GREEN}[✓] Test page generated: {test_file}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  MANUAL TESTING REQUIRED:{Style.RESET_ALL}")
        print(f"   1. Open {test_file} in a web browser")
        print(f"   2. If you see the decoy button OVER the target page → VULNERABLE")
        print(f"   3. If target page is blocked or shows error → PROTECTED")
        print(f"   4. Test with authenticated session for accurate results")

        print(f"\n{Fore.CYAN}Visual indicators:{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}• Target page NOT visible through decoy = PROTECTED{Style.RESET_ALL}")
        print(f"   {Fore.RED}• Target page visible under decoy button = VULNERABLE{Style.RESET_ALL}")
        print(f"   {Fore.YELLOW}• Target page shows clickjacking warning = PARTIALLY PROTECTED{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if vulnerable:
            print(f"\n{Fore.RED}[!] CLICKJACKING VULNERABILITY CONFIRMED{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Risk Level: MEDIUM to HIGH{Style.RESET_ALL}")
            print(f"   • Attackers can trick users into clicking hidden elements")
            print(f"   • Account takeover, unauthorized transactions, data leaks")
            print(f"   • Social engineering attacks with high success rate")

            print(f"\n{Fore.YELLOW}Critical Fixes:{Style.RESET_ALL}")
            print(f"   • Add X-Frame-Options header:")
            print(f"        X-Frame-Options: DENY          (blocks all framing)")
            print(f"        X-Frame-Options: SAMEORIGIN    (allows same-origin only)")
            print(f"   • OR implement Content-Security-Policy:")
            print(f"        Content-Security-Policy: frame-ancestors 'none';")
            print(f"        Content-Security-Policy: frame-ancestors 'self';")
            print(f"   • For legacy browsers: implement frame-busting JavaScript:")
            print(f"        if (top != self) top.location = self.location;")
            print(f"   • Test protection in all major browsers (Chrome, Firefox, Safari, Edge)")
        else:
            if protection_level == "GOOD":
                print(f"\n{Fore.GREEN}[✓] Strong clickjacking protection detected{Style.RESET_ALL}")
            elif protection_level == "PARTIAL":
                print(f"\n{Fore.YELLOW}[!] Partial protection detected - improvements recommended{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Best Practices:{Style.RESET_ALL}")
            print(f"   • Prefer CSP frame-ancestors over X-Frame-Options (modern standard)")
            print(f"   • Use 'DENY' for pages that should never be framed")
            print(f"   • Use 'SAMEORIGIN' only when necessary for legitimate framing")
            print(f"   • Test protection with authenticated sessions")
            print(f"   • Monitor for new bypass techniques")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Clickjacking analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL NOTE:{Style.RESET_ALL}")
        print(f"   Generated test pages are for educational purposes ONLY.")
        print(f"   Never use deceptive UIs for actual attacks or phishing.")
        print(f"   Always obtain written authorization before testing.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")