import requests
import urllib.parse
import re
import time
import sys
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

# =======================
# Banner
# =======================
def show_banner():
    print(r"""
      ___           ___           ___                   ___           ___           ___     
     /\  \         /\  \         /\__\      ___        /\  \         |\__\         /\  \    
    /::\  \       /::\  \       /:/  /     /\  \      /::\  \        |:|  |       /::\  \   
   /:/\ \  \     /:/\:\  \     /:/  /      \:\  \    /:/\:\  \       |:|  |      /:/\:\  \  
  _\:\~\ \  \    \:\~\:\  \   /:/  /       /::\__\  /::\~\:\  \      |:|__|__   /::\~\:\  \ 
 /\ \:\ \ \__\    \:\ \:\__\ /:/__/     __/:/\/__/ /:/\:\ \:\__\     /::::\__\ /:/\:\ \:\__\
 \:\ \:\ \/__/     \:\/:/  / \:\  \    /\/:/  /    \:\~\:\ \/__/    /:/~~/~    \:\~\:\ \/__/
  \:\ \:\__\        \::/  /   \:\  \   \::/__/      \:\ \:\__\     /:/  /       \:\ \:\__\  
   \:\/:/  /        /:/  /     \:\  \   \:\__\       \:\ \/__/     \/__/         \:\ \/__/  
    \::/  /        /:/  /       \:\__\   \/__/        \:\__\                      \:\__\    
     \/__/         \/__/         \/__/                 \/__/                       \/__/    

        Aԃʋαɳƈҽԃ SQL Iɳʝҽƈƚισɳ Dҽƚҽƈƚσɾ
""")


DB_ERRORS = [
    "sql syntax", "mysql", "mssql", "oracle", "postgresql",
    "sqlite", "odbc", "syntax error", "unclosed quotation",
    "quoted string not properly terminated", "sql error",
    "warning: mysql", "you have an error in your sql syntax",
    "invalid query", "pdoexception", "mysqli", "sqlstate"
]

PAYLOADS = {
    "error": ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"],
    "boolean": [
        "1' AND 1=1-- -", "1' AND 1=2-- -",
        "1\" AND 1=1-- -", "1\" AND 1=2-- -"
    ],
    "time": [
        "1' AND SLEEP(5)-- -",
        "1\" AND PG_SLEEP(5)-- -",
        "1; WAITFOR DELAY '0:0:5'--"
    ]
}


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

def test_url_parameter(url, param, payloads, is_get=True):
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for ptype, plist in payloads.items():
        for payload in plist:
            try:
                start = time.time()
                if is_get:
                    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    q[param] = payload
                    test_url = base_url + "?" + urllib.parse.urlencode(q, doseq=True)
                    resp = requests.get(test_url, timeout=10, verify=False)
                else:
                    resp = requests.post(url, data={param: payload}, timeout=10, verify=False)

                delay = time.time() - start
                content = resp.text.lower()

                for err in DB_ERRORS:
                    if err in content:
                        return True, f"DB error detected: {err}"

                if ptype == "time" and delay > 4:
                    return True, "Time-based SQLi detected"

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

    print("\n[+] Checking GET parameters...")
    parsed = urllib.parse.urlparse(target)

    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            print(f" → Testing GET parameter: {param}")
            vuln, reason = test_url_parameter(target, param, PAYLOADS, is_get=True)
            if vuln:
                print(f"   [!] VULNERABLE → {reason}")
            else:
                print("   [✓] Safe")
    else:
        print(" [i] No GET parameters found")

    print("\n[+] Checking HTML forms...")
    forms = get_forms(target)

    if forms:
        print(f"[✓] Found {len(forms)} form(s)")
        for i, form in enumerate(forms, 1):
            print(f"\n → Form #{i}: {form['method'].upper()} → {form['action']}")
            for param in form["inputs"]:
                print(f"   Testing field: {param}")
                vuln, reason = test_url_parameter(form["action"], param, PAYLOADS, is_get=False)
                if vuln:
                    print(f"     [!] VULNERABLE → {reason}")
                else:
                    print("     [✓] Safe")
    else:
        print("[i] No forms found")

    print("\n[+] Checking base page for DB errors...")
    try:
        resp = requests.get(target, timeout=5, verify=False)
        found = False
        for err in DB_ERRORS:
            if err in resp.text.lower():
                print(f"   [!] Possible DB error: {err}")
                found = True
        if not found:
            print("   [✓] No DB errors detected")
    except:
        print("   [!] Failed to fetch base page")

    print("\n[✓] SQLi analysis completed")
    input("\nPress Enter to return to main menu...")
    return


if __name__ == "__main__":
    run()
