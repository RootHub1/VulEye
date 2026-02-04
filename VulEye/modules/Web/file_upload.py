import requests
from bs4 import BeautifulSoup
import re
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              FILE UPLOAD VULNERABILITY SCANNER                    {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (page with file upload form): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing page for file upload forms{Style.RESET_ALL}")

    try:
        response = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        upload_forms = []
        for form in forms:
            if form.find('input', {'type': 'file'}):
                upload_forms.append(form)

        if not upload_forms:
            print(f"\n{Fore.RED}[!] No file upload forms detected on page.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Look for: <input type='file'> elements{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[✓] Found {len(upload_forms)} file upload form(s){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}UPLOAD FORM ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        for i, form in enumerate(upload_forms, 1):
            action = form.get('action', target)
            if not action.startswith(('http://', 'https://')):
                from urllib.parse import urljoin
                action = urljoin(target, action)

            method = form.get('method', 'post').upper()
            file_inputs = form.find_all('input', {'type': 'file'})

            print(f"\n{Fore.CYAN}Form #{i}{Style.RESET_ALL}")
            print(f"   Action: {action}")
            print(f"   Method: {method}")

            for inp in file_inputs:
                name = inp.get('name', 'unknown')
                accept = inp.get('accept', 'Not specified')
                print(f"   File input: name='{name}', accept='{accept}'")

            if form.find('input', {'type': 'hidden', 'name': re.compile('csrf|token')}):
                print(f"   {Fore.GREEN}[✓] CSRF protection detected{Style.RESET_ALL}")
            else:
                print(f"   {Fore.YELLOW}[!] No CSRF token detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}VULNERABILITY TESTING (SAFE MODE){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: Only harmless test files will be uploaded{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        test_files = [
            ('test.txt', b'Test file - harmless content', 'text/plain', 'Basic text file'),
            ('test.jpg', b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01', 'image/jpeg', 'JPEG image header'),
            ('test.php.txt', b'<?php echo "test"; ?>', 'text/plain', 'Double extension bypass attempt'),
            ('test.pHp', b'<?php echo "test"; ?>', 'text/plain', 'Case manipulation bypass attempt'),
            ('test.php.jpg', b'\xff\xd8\xff\xe0<?php', 'image/jpeg', 'Embedded PHP in image'),
        ]

        vulnerable = False
        upload_endpoint = None
        file_param = None

        if upload_forms:
            form = upload_forms[0]
            upload_endpoint = form.get('action', target)
            if not upload_endpoint.startswith(('http://', 'https://')):
                from urllib.parse import urljoin
                upload_endpoint = urljoin(target, upload_endpoint)
            file_input = form.find('input', {'type': 'file'})
            file_param = file_input.get('name', 'file')

        print(f"\n{Fore.CYAN}[→] Testing upload endpoint: {upload_endpoint}{Style.RESET_ALL}")
        print(f"    File parameter: {file_param}")

        for filename, content, mime_type, description in test_files:
            try:
                files = {file_param: (filename, content, mime_type)}
                response = requests.post(upload_endpoint, files=files, timeout=10, verify=False)

                success_indicators = [
                    'upload successful', 'file uploaded', 'success',
                    'location:', '.com/uploads/', 'href=', 'url='
                ]

                if any(ind in response.text.lower() for ind in success_indicators) or response.status_code in [200, 201,
                                                                                                               202]:
                    if '.php' in filename.lower() or '<?php' in content.decode('latin-1', errors='ignore'):
                        vulnerable = True
                        print(
                            f"{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL: Potentially executable file accepted{Style.RESET_ALL}")
                        print(f"    File: {filename}")
                        print(f"    Description: {description}")
                        print(f"    Status: {response.status_code}")
                        print(f"    {Fore.YELLOW}⚠️  SERVER ACCEPTED FILE THAT COULD CONTAIN CODE{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[✓] Accepted: {filename} ({description}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[i] Rejected: {filename} ({description}){Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.YELLOW}[?] Error testing {filename}: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if vulnerable:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL FILE UPLOAD VULNERABILITY DETECTED{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Risk Level: CRITICAL{Style.RESET_ALL}")
            print(f"   • Remote code execution possible via uploaded webshell")
            print(f"   • Full server compromise likely")
            print(f"   • Data theft, defacement, or malware distribution")

            print(f"\n{Fore.YELLOW}Immediate Mitigations:{Style.RESET_ALL}")
            print(f"   • Implement strict allowlist for file extensions:")
            print(f"        ALLOWED = ['.jpg', '.png', '.pdf', '.docx']")
            print(f"        if not filename.lower().endswith(tuple(ALLOWED)): reject()")
            print(f"   • Store uploaded files OUTSIDE web root directory")
            print(f"   • Rename files to random UUIDs (no original filenames)")
            print(f"   • Scan files with antivirus (ClamAV)")
            print(f"   • Set proper file permissions (no execute bits)")
            print(f"   • Validate file content (magic bytes), not just extension")
            print(f"   • Use separate domain for uploaded content (cdn.yoursite.com)")
            print(f"   • Implement Content Security Policy (CSP) headers")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical vulnerabilities detected in safe tests{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Important Notes:{Style.RESET_ALL}")
            print(f"   • This scan used ONLY harmless test files")
            print(f"   • Advanced bypasses require manual testing:")
            print(f"        - Null byte injection (%00)")
            print(f"        - MIME type manipulation")
            print(f"        - ZIP upload with .htaccess")
            print(f"        - Polyglot files (image + PHP)")
            print(f"   • Always test on isolated environment first")
            print(f"   • Verify file storage location and permissions")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] File upload analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}⚠️  LEGAL WARNING:{Style.RESET_ALL}")
        print(f"   Uploading files without authorization is illegal in most jurisdictions.")
        print(f"   Even harmless files may violate terms of service.")
        print(f"   Always obtain written permission before testing.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")