import requests
from colorama import init, Fore, Style

init(autoreset=True)


def generate_test_page(target_url, output_file="clickjacking_test.html"):
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Clickjacking Test</title>
<style>
body {{ margin:0; padding:0; overflow:hidden; }}
#overlay {{
 position:absolute;
 top:50%;
 left:50%;
 transform:translate(-50%,-50%);
 background:rgba(220,53,69,.9);
 color:#fff;
 padding:20px;
 border-radius:10px;
 z-index:10;
 text-align:center;
 font-family:Arial;
}}
iframe {{
 position:absolute;
 top:0;
 left:0;
 width:100%;
 height:100%;
 border:none;
 z-index:1;
 opacity:.85;
}}
</style>
</head>
<body>
<div id="overlay">
<h2>FREE GIFT</h2>
<button style="padding:12px 25px;font-size:18px;">CLAIM</button>
</div>
<iframe src="{target_url}"></iframe>
</body>
</html>"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    return output_file


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} CLICKJACKING TESTER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
        input()
        return

    try:
        r = requests.get(target, timeout=10, verify=False)
        h = r.headers

        xfo = h.get("X-Frame-Options", "").upper()
        csp = h.get("Content-Security-Policy", "")

        frame_ancestors = None
        for part in csp.split(";"):
            if "frame-ancestors" in part.lower():
                frame_ancestors = part.strip().lower()

        vulnerable = False
        level = "NONE"

        if not xfo and not frame_ancestors:
            vulnerable = True
        else:
            if xfo in ["DENY", "SAMEORIGIN"]:
                level = "GOOD"
            elif xfo:
                level = "PARTIAL"

            if frame_ancestors:
                if "'none'" in frame_ancestors or "'self'" in frame_ancestors or "https://" in frame_ancestors:
                    level = "GOOD"
                else:
                    level = "PARTIAL"

        print(f"\nX-Frame-Options: {xfo or 'NOT SET'}")
        print(f"CSP frame-ancestors: {frame_ancestors or 'NOT SET'}")

        test_file = generate_test_page(target)

        print(f"\nTest page: {test_file}")

        if vulnerable:
            print(f"\n{Fore.RED}[!] CLICKJACKING VULNERABLE{Style.RESET_ALL}")
        else:
            if level == "GOOD":
                print(f"\n{Fore.GREEN}[✓] PROTECTED{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[!] PARTIAL PROTECTION{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
