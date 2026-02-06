import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import init, Fore, Style
import re
import urllib3

urllib3.disable_warnings()
init(autoreset=True)


def detect_technologies(response, soup):
    text = response.text.lower()
    headers = response.headers
    tech = set()

    server = headers.get("Server", "")
    if server:
        tech.add(("Server", server))
        if "nginx" in server.lower():
            tech.add(("Web Server", "nginx"))
        elif "apache" in server.lower():
            tech.add(("Web Server", "Apache"))
        elif "iis" in server.lower():
            tech.add(("Web Server", "Microsoft IIS"))
        elif "lighttpd" in server.lower():
            tech.add(("Web Server", "Lighttpd"))

    powered = headers.get("X-Powered-By", "")
    if powered:
        tech.add(("X-Powered-By", powered))
        if "php" in powered.lower():
            tech.add(("Language", "PHP"))
        elif "asp.net" in powered.lower():
            tech.add(("Language", "ASP.NET"))
        elif "python" in powered.lower():
            tech.add(("Language", "Python"))
        elif "node" in powered.lower():
            tech.add(("Runtime", "Node.js"))

    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        tech.add(("Generator", generator["content"]))

    if any(x in text for x in ["/wp-content/", "/wp-includes/", "wp-json"]):
        tech.add(("CMS", "WordPress"))
        m = re.search(r"wordpress\s*([\d.]+)", text)
        if m:
            tech.add(("WordPress Version", m.group(1)))

    if any(x in text for x in ["/sites/default/", "drupal"]):
        tech.add(("CMS", "Drupal"))

    if any(x in text for x in ["/media/system/", "joomla"]):
        tech.add(("CMS", "Joomla"))

    if any(x in text for x in ["/skin/frontend/", "magento"]):
        tech.add(("E-commerce", "Magento"))

    if "prestashop" in text:
        tech.add(("E-commerce", "PrestaShop"))

    if "shopware" in text:
        tech.add(("E-commerce", "Shopware"))

    if "react" in text or "__react" in text:
        tech.add(("Framework", "React"))

    if "angular" in text or "ng-app" in text:
        tech.add(("Framework", "Angular"))

    if "vue" in text or "__vue" in text:
        tech.add(("Framework", "Vue.js"))

    if "jquery" in text:
        tech.add(("Library", "jQuery"))
        m = re.search(r"jquery[-./]([\d.]+)", text)
        if m:
            tech.add(("jQuery Version", m.group(1)))

    if "bootstrap" in text:
        tech.add(("Framework", "Bootstrap"))
        m = re.search(r"bootstrap[-./]([\d.]+)", text)
        if m:
            tech.add(("Bootstrap Version", m.group(1)))

    if "font-awesome" in text:
        tech.add(("Library", "Font Awesome"))

    if "cloudflare" in text or "cf-ray" in headers:
        tech.add(("CDN", "Cloudflare"))

    if "akamai" in text:
        tech.add(("CDN", "Akamai"))

    if "fastly" in text:
        tech.add(("CDN", "Fastly"))

    if any(x in text for x in ["amazonaws.com", "cloudfront"]):
        tech.add(("Cloud", "AWS"))

    if "firebase" in text:
        tech.add(("Service", "Firebase"))

    if "stripe" in text:
        tech.add(("Payment", "Stripe"))

    if "paypal" in text:
        tech.add(("Payment", "PayPal"))

    if "google-analytics" in text or "analytics.js" in text:
        tech.add(("Analytics", "Google Analytics"))

    if "recaptcha" in text:
        tech.add(("Security", "reCAPTCHA"))

    if ".php" in text and "php" not in powered.lower():
        tech.add(("Language", "PHP"))

    if any(x in text for x in [".asp", ".aspx"]):
        tech.add(("Language", "ASP.NET"))

    if any(x in text for x in [".jsp", "java"]):
        tech.add(("Language", "Java/JSP"))

    if "rails" in text or "ruby" in server.lower():
        tech.add(("Language", "Ruby on Rails"))

    if "django" in text or "flask" in text:
        tech.add(("Language", "Python"))

    if "express" in text or "node" in server.lower():
        tech.add(("Runtime", "Node.js"))

    return sorted(tech, key=lambda x: x[0])


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}            TECHNOLOGY STACK DETECTOR                            {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target or not target.startswith(("http://", "https://")):
        return

    try:
        response = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        print(f"\n{Fore.GREEN}[✓] Connected ({response.status_code}){Style.RESET_ALL}")

        techs = detect_technologies(response, soup)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}DETECTED TECHNOLOGIES")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if techs:
            for name, value in techs:
                print(f"{Fore.CYAN}• {name}:{Style.RESET_ALL} {value}")
        else:
            print(f"{Fore.YELLOW}No technologies detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}PAGE INFO")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"Server: {response.headers.get('Server', 'Hidden')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"Page Size: {len(response.content)} bytes")
        print(f"Connection: {urlparse(target).scheme.upper()}")

        print(f"\n{Fore.GREEN}[✓] Detection completed{Style.RESET_ALL}")

    except requests.RequestException as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    run()
