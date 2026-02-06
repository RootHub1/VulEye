import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} FILE UPLOAD VULNERABILITY SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        input()
        return

    session = requests.Session()
    session.verify = False

    try:
        r = session.get(target, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        upload_forms = [f for f in forms if f.find("input", {"type": "file"})]

        if not upload_forms:
            print(f"{Fore.RED}[!] No upload forms found{Style.RESET_ALL}")
            input()
            return

        print(f"{Fore.GREEN}[✓] Upload forms found: {len(upload_forms)}{Style.RESET_ALL}")

        form = upload_forms[0]
        action = urljoin(target, form.get("action") or target)
        method = form.get("method", "POST").upper()
        file_input = form.find("input", {"type": "file"})
        file_param = file_input.get("name", "file")

        print(f"\nAction: {action}")
        print(f"Method: {method}")
        print(f"File field: {file_param}")

        csrf_present = bool(form.find("input", {"type": "hidden", "name": re.compile("csrf|token", re.I)}))
        print(f"{Fore.GREEN}[✓] CSRF detected{Style.RESET_ALL}" if csrf_present else f"{Fore.YELLOW}[!] No CSRF token{Style.RESET_ALL}")

        test_files = [
            ("test.txt", b"test", "text/plain"),
            ("test.jpg", b"\xff\xd8\xff\xe0", "image/jpeg"),
            ("test.php.txt", b"<?php echo 1;?>", "text/plain"),
            ("test.pHp", b"<?php echo 1;?>", "text/plain"),
            ("test.php.jpg", b"\xff\xd8\xff\xe0<?php", "image/jpeg"),
        ]

        vulnerable = False

        print(f"\n{Fore.CYAN}Testing uploads{Style.RESET_ALL}")

        for name, content, mime in test_files:
            try:
                files = {file_param: (name, content, mime)}
                resp = session.post(action, files=files, timeout=10)

                accepted = resp.status_code in (200, 201, 202)
                dangerous = ".php" in name.lower() or b"<?php" in content

                if accepted and dangerous:
                    vulnerable = True
                    print(f"{Fore.MAGENTA}[!] Dangerous file accepted: {name}{Style.RESET_ALL}")
                elif accepted:
                    print(f"{Fore.GREEN}[✓] Accepted: {name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[i] Rejected: {name}{Style.RESET_ALL}")

            except Exception:
                print(f"{Fore.YELLOW}[?] Error testing {name}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if vulnerable:
            print(f"{Fore.MAGENTA}[!] FILE UPLOAD VULNERABILITY DETECTED{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No critical upload issues detected{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
