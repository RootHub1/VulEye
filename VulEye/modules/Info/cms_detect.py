import requests
from bs4 import BeautifulSoup
import re
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              CMS DETECTOR                                          {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (http:// or https://): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Detecting CMS for: {target}{Style.RESET_ALL}")

    try:
        response = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CMS DETECTION RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        cms_detected = []
        confidence = "Medium"

        if '/wp-content/' in response.text or '/wp-includes/' in response.text or '/wp-admin/' in response.text:
            cms_detected.append(('WordPress', 'High'))
            wp_version = None
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'WordPress' in meta_generator.get('content', ''):
                wp_version = meta_generator['content'].replace('WordPress ', '')
            if wp_version:
                cms_detected.append((f'WordPress Version: {wp_version}', 'High'))
            else:
                cms_detected.append(('WordPress Version: Unknown', 'Medium'))
            if '/xmlrpc.php' in response.text:
                cms_detected.append(('WordPress XML-RPC: Enabled', 'Medium'))
            if 'wp-json' in response.text or 'rest_route' in response.text:
                cms_detected.append(('WordPress REST API: Enabled', 'Medium'))

        if '/media/system/' in response.text or 'joomla' in response.text.lower() or '/components/com_' in response.text:
            cms_detected.append(('Joomla', 'High'))
            joomla_version = None
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'Joomla' in meta_generator.get('content', ''):
                joomla_version = meta_generator['content'].replace('Joomla!', '').replace('Joomla', '').strip()
            if joomla_version:
                cms_detected.append((f'Joomla Version: {joomla_version}', 'High'))
            else:
                cms_detected.append(('Joomla Version: Unknown', 'Medium'))

        if '/sites/default/' in response.text or 'drupal' in response.text.lower() or '/misc/drupal.js' in response.text:
            cms_detected.append(('Drupal', 'High'))
            drupal_version = None
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'Drupal' in meta_generator.get('content', ''):
                drupal_version = meta_generator['content'].replace('Drupal ', '')
            if drupal_version:
                cms_detected.append((f'Drupal Version: {drupal_version}', 'High'))
            else:
                cms_detected.append(('Drupal Version: Unknown', 'Medium'))

        if '/skin/frontend/' in response.text or 'magento' in response.text.lower() or '/js/mage/' in response.text:
            cms_detected.append(('Magento', 'High'))
            magento_version = None
            if 'mage-' in response.text or 'prototype.js' in response.text:
                magento_version = '1.x (detected by patterns)'
            elif 'Magento_Customer/js' in response.text:
                magento_version = '2.x (detected by patterns)'
            if magento_version:
                cms_detected.append((f'Magento Version: {magento_version}', 'Medium'))
            else:
                cms_detected.append(('Magento Version: Unknown', 'Medium'))

        if '/prestashop/' in response.text or 'prestashop' in response.text.lower() or '/js/jquery/plugins/' in response.text:
            cms_detected.append(('PrestaShop', 'High'))
            prestashop_version = None
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'PrestaShop' in meta_generator.get('content', ''):
                prestashop_version = meta_generator['content'].replace('PrestaShop ', '')
            if prestashop_version:
                cms_detected.append((f'PrestaShop Version: {prestashop_version}', 'High'))
            else:
                cms_detected.append(('PrestaShop Version: Unknown', 'Medium'))

        if 'cdn.shopify.com' in response.text or 'shopify' in response.text.lower():
            cms_detected.append(('Shopify', 'High'))
            shopify_version = None
            if 'Shopify.theme' in response.text or 'Shopify.currencies' in response.text:
                shopify_version = 'Detected (Shopify platform)'
            if shopify_version:
                cms_detected.append((f'Shopify: {shopify_version}', 'High'))

        if 'wix.com' in response.text or 'wix-' in response.text.lower() or 'wixapps' in response.text:
            cms_detected.append(('Wix', 'High'))

        if 'squarespace' in response.text.lower() or 'squarespace.com' in response.text:
            cms_detected.append(('Squarespace', 'High'))

        if 'ghost' in response.text.lower() or '/ghost/' in response.text or 'Ghost' in headers.get('X-Ghost-Version',
                                                                                                    ''):
            cms_detected.append(('Ghost', 'High'))
            ghost_version = headers.get('X-Ghost-Version', 'Unknown')
            cms_detected.append((f'Ghost Version: {ghost_version}', 'Medium'))

        if 'typo3' in response.text.lower() or '/typo3/' in response.text or 'TYPO3' in response.text:
            cms_detected.append(('TYPO3', 'High'))
            typo3_version = None
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'TYPO3' in meta_generator.get('content', ''):
                typo3_version = meta_generator['content'].replace('TYPO3 ', '')
            if typo3_version:
                cms_detected.append((f'TYPO3 Version: {typo3_version}', 'High'))
            else:
                cms_detected.append(('TYPO3 Version: Unknown', 'Medium'))

        if 'blogger' in response.text.lower() or 'blogspot' in response.text.lower():
            cms_detected.append(('Blogger', 'High'))

        if 'medium.com' in response.text.lower() or 'medium' in response.text.lower():
            cms_detected.append(('Medium', 'High'))

        if not cms_detected:
            cms_detected.append(('No CMS detected (Static site or custom)', 'Low'))
            confidence = "Low"

        if cms_detected:
            print(f"\n{Fore.GREEN}[✓] Detected CMS:{Style.RESET_ALL}")
            for cms, conf in cms_detected:
                conf_color = Fore.RED if conf == 'High' else (Fore.YELLOW if conf == 'Medium' else Fore.CYAN)
                print(f"   {conf_color}• {cms} ({conf} confidence){Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No CMS detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL INFORMATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}HTTP Headers Analysis:{Style.RESET_ALL}")
        print(f"   Status Code: {response.status_code}")
        print(f"   Content-Type: {headers.get('Content-Type', 'Not specified')}")
        print(f"   Server: {headers.get('Server', 'Not disclosed')}")

        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            print(f"   Meta Generator: {meta_generator.get('content', 'N/A')}")

        meta_description = soup.find('meta', attrs={'name': 'description'})
        if meta_description:
            desc = meta_description.get('content', '')[:100]
            print(f"   Meta Description: {desc}...")

        title = soup.title.string if soup.title else 'No title'
        print(f"   Page Title: {title[:100]}...")

        content_length = len(response.content)
        print(f"   Page Size: {content_length} bytes ({content_length / 1024:.2f} KB)")

        if 'https' in target:
            print(f"{Fore.GREEN}   Connection: HTTPS (Secure){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}   Connection: HTTP (Not encrypted){Style.RESET_ALL}")

        if cms_detected and cms_detected[0][1] == 'High':
            print(f"\n{Fore.CYAN}{'=' * 70}")
            print(f"{Fore.CYAN}SECURITY RECOMMENDATIONS")
            print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

            cms_name = cms_detected[0][0].split()[0]

            if cms_name == 'WordPress':
                print(f"\n{Fore.YELLOW}WordPress Security Tips:{Style.RESET_ALL}")
                print(f"   • Keep WordPress core, themes, and plugins updated")
                print(f"   • Remove unused themes and plugins")
                print(f"   • Disable XML-RPC if not needed")
                print(f"   • Use strong passwords and 2FA")
                print(f"   • Install security plugin (Wordfence, Sucuri)")
                print(f"   • Hide WordPress version in headers")

            elif cms_name == 'Joomla':
                print(f"\n{Fore.YELLOW}Joomla Security Tips:{Style.RESET_ALL}")
                print(f"   • Keep Joomla core and extensions updated")
                print(f"   • Use strong admin passwords")
                print(f"   • Enable 2FA for administrator accounts")
                print(f"   • Disable unused components and modules")
                print(f"   • Configure proper file permissions")

            elif cms_name == 'Drupal':
                print(f"\n{Fore.YELLOW}Drupal Security Tips:{Style.RESET_ALL}")
                print(f"   • Keep Drupal core and modules updated")
                print(f"   • Use strong admin credentials")
                print(f"   • Enable Security Kit module")
                print(f"   • Configure proper permissions")
                print(f"   • Disable unused modules")

            elif cms_name == 'Magento':
                print(f"\n{Fore.YELLOW}Magento Security Tips:{Style.RESET_ALL}")
                print(f"   • Keep Magento and extensions updated")
                print(f"   • Use strong admin passwords")
                print(f"   • Enable 2FA for admin panel")
                print(f"   • Disable Magento Connect Manager if not needed")
                print(f"   • Configure proper file permissions")

            elif cms_name == 'PrestaShop':
                print(f"\n{Fore.YELLOW}PrestaShop Security Tips:{Style.RESET_ALL}")
                print(f"   • Keep PrestaShop and modules updated")
                print(f"   • Use strong admin passwords")
                print(f"   • Disable unused modules")
                print(f"   • Enable SSL for admin panel")
                print(f"   • Configure proper file permissions")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] CMS detection completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")