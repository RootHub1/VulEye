import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import init, Fore, Style
import urllib3

urllib3.disable_warnings()
init(autoreset=True)


def detect_cms(response, soup):
    text = response.text.lower()
    headers = response.headers
    results = []

    def meta_generator_contains(value):
        tag = soup.find("meta", attrs={"name": "generator"})
        return tag and value.lower() in tag.get("content", "").lower()

    if any(x in text for x in ["/wp-content/", "/wp-includes/", "/wp-admin/"]):
        results.append(("WordPress", "High"))
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and "wordpress" in tag.get("content", "").lower():
            results.append((f"WordPress Version: {tag.get('content').replace('WordPress', '').strip()}", "High"))

    if any(x in text for x in ["/components/com_", "/media/system/"]) or meta_generator_contains("joomla"):
        results.append(("Joomla", "High"))
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and "joomla" in tag.get("content", "").lower():
            results.append((f"Joomla Version: {tag.get('content').replace('Joomla!', '').strip()}", "High"))

    if any(x in text for x in ["/sites/default/", "/misc/drupal.js"]) or meta_generator_contains("drupal"):
        results.append(("Drupal", "High"))
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and "drupal" in tag.get("content", "").lower():
            results.append((f"Drupal Version: {tag.get('content').replace('Drupal', '').strip()}", "High"))

    if any(x in text for x in ["/skin/frontend/", "/js/mage/"]) or "magento" in text:
        results.append(("Magento", "High"))
        if "mage-" in text:
            results.append(("Magento Version: 1.x", "Medium"))
        elif "magento_customer/js" in text:
            results.append(("Magento Version: 2.x", "Medium"))

    if "prestashop" in text:
        results.append(("PrestaShop", "High"))
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and "prestashop" in tag.get("content", "").lower():
            results.append((f"PrestaShop Version: {tag.get('content').replace('PrestaShop', '').strip()}", "High"))

    if "cdn.shopify.com" in text or "shopify" in text:
        results.append(("Shopify", "High"))

    if any(x in text for x in ["wix.com", "wixapps", "wix-"]):
        results.append(("Wix", "High"))

    if "squarespace" in text:
        results.append(("Squarespace", "High"))

    if "/ghost/" in text or "ghost" in headers.get("X-Ghost-Version", ""):
        results.append(("Ghost", "High"))
        results.append((f"Ghost Version: {headers.get('X-Ghost-Version', 'Unknown')}", "Medium"))

    if "typo3" in text:
        results.append(("TYPO3", "High"))
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and "typo3" in tag.get("content", "").lower():
            results.append((f"TYPO3 Version: {tag.get('content').replace('TYPO3', '').strip()}", "High"))

    if any(x in text for x in ["blogspot", "blogger"]):
        results.append(("Blogger", "High"))

    if "medium.com" in text:
        results.append(("Medium", "High"))

    return results


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}                  CMS DETECTOR                                   {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL: {Style.RESET_ALL}").strip()
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        print(f"{Fore.RED}Invalid URL scheme{Style.RESET_ALL}")
        return

    try:
        response = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        print(f"\n{Fore.GREEN}[✓] Connected ({response.status_code}){Style.RESET_ALL}")

        cms_results = detect_cms(response, soup)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CMS DETECTION RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if cms_results:
            for item, confidence in cms_results:
                color = Fore.RED if confidence == "High" else Fore.YELLOW
                print(f"{color}• {item} ({confidence}){Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}• No CMS detected (custom or static site){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}PAGE INFORMATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"Status Code: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'Hidden')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"Page Size: {len(response.content)} bytes")

        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        print(f"Title: {title[:100]}")

        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            print(f"Meta Generator: {generator.get('content', 'N/A')}")

        scheme = urlparse(target).scheme
        print(f"Connection: {'HTTPS' if scheme == 'https' else 'HTTP'}")

        print(f"\n{Fore.GREEN}[✓] Scan completed{Style.RESET_ALL}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    run()
