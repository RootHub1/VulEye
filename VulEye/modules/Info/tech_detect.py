import requests
from bs4 import BeautifulSoup
import re
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              TECHNOLOGY STACK DETECTOR                             {Fore.CYAN}║")
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

    print(f"\n{Fore.CYAN}[+] Detecting technologies for: {target}{Style.RESET_ALL}")

    try:
        response = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}TECHNOLOGY DETECTION RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        technologies = []

        server = headers.get('Server', '')
        if server:
            technologies.append(('Server', server))
            if 'apache' in server.lower():
                technologies.append(('Web Server', 'Apache'))
            elif 'nginx' in server.lower():
                technologies.append(('Web Server', 'nginx'))
            elif 'iis' in server.lower():
                technologies.append(('Web Server', 'Microsoft IIS'))
            elif 'lighttpd' in server.lower():
                technologies.append(('Web Server', 'Lighttpd'))

        x_powered_by = headers.get('X-Powered-By', '')
        if x_powered_by:
            technologies.append(('X-Powered-By', x_powered_by))
            if 'php' in x_powered_by.lower():
                technologies.append(('Language', 'PHP'))
            elif 'asp.net' in x_powered_by.lower():
                technologies.append(('Language', 'ASP.NET'))
            elif 'python' in x_powered_by.lower():
                technologies.append(('Language', 'Python'))
            elif 'node.js' in x_powered_by.lower():
                technologies.append(('Runtime', 'Node.js'))

        if '/wp-content/' in response.text or '/wp-includes/' in response.text:
            technologies.append(('CMS', 'WordPress'))
            wp_version = re.search(r'<meta name="generator" content="WordPress ([\d.]+)', response.text)
            if wp_version:
                technologies.append(('WordPress Version', wp_version.group(1)))

        if '/sites/default/' in response.text or 'drupal' in response.text.lower():
            technologies.append(('CMS', 'Drupal'))
            drupal_version = re.search(r'<meta name="generator" content="Drupal ([\d.]+)', response.text)
            if drupal_version:
                technologies.append(('Drupal Version', drupal_version.group(1)))

        if '/media/system/' in response.text or 'joomla' in response.text.lower():
            technologies.append(('CMS', 'Joomla'))

        if '/skin/frontend/' in response.text or 'magento' in response.text.lower():
            technologies.append(('E-commerce', 'Magento'))

        if '/static/shopware/' in response.text or 'shopware' in response.text.lower():
            technologies.append(('E-commerce', 'Shopware'))

        if '/prestashop/' in response.text or 'prestashop' in response.text.lower():
            technologies.append(('E-commerce', 'PrestaShop'))

        if 'wp-json' in response.text or 'rest_route' in response.text:
            technologies.append(('API', 'WordPress REST API'))

        if 'react' in response.text.lower() or '__react' in response.text:
            technologies.append(('Framework', 'React'))

        if 'angular' in response.text.lower() or 'ng-app' in response.text or 'ng-controller' in response.text:
            technologies.append(('Framework', 'Angular'))

        if 'vue' in response.text.lower() or '__vue' in response.text:
            technologies.append(('Framework', 'Vue.js'))

        if 'jquery' in response.text.lower():
            technologies.append(('Library', 'jQuery'))
            jquery_version = re.search(r'jquery/([\d.]+)', response.text, re.IGNORECASE)
            if jquery_version:
                technologies.append(('jQuery Version', jquery_version.group(1)))

        if 'bootstrap' in response.text.lower():
            technologies.append(('Framework', 'Bootstrap'))
            bootstrap_version = re.search(r'bootstrap/([\d.]+)', response.text, re.IGNORECASE)
            if bootstrap_version:
                technologies.append(('Bootstrap Version', bootstrap_version.group(1)))

        if 'font-awesome' in response.text.lower():
            technologies.append(('Library', 'Font Awesome'))

        if 'googleapis.com' in response.text:
            technologies.append(('CDN', 'Google APIs'))

        if 'cloudflare' in response.text.lower() or 'cf-ray' in headers:
            technologies.append(('CDN', 'Cloudflare'))

        if 'akamai' in response.text.lower():
            technologies.append(('CDN', 'Akamai'))

        if 'fastly' in response.text.lower():
            technologies.append(('CDN', 'Fastly'))

        if 'amazonaws.com' in response.text or 'cloudfront' in response.text.lower():
            technologies.append(('Cloud', 'AWS'))

        if 'firebase' in response.text.lower():
            technologies.append(('Service', 'Firebase'))

        if 'stripe' in response.text.lower():
            technologies.append(('Payment', 'Stripe'))

        if 'paypal' in response.text.lower():
            technologies.append(('Payment', 'PayPal'))

        if 'google-analytics' in response.text.lower() or 'analytics.js' in response.text:
            technologies.append(('Analytics', 'Google Analytics'))

        if 'recaptcha' in response.text.lower():
            technologies.append(('Security', 'reCAPTCHA'))

        if 'cloudinary' in response.text.lower():
            technologies.append(('Service', 'Cloudinary (Image CDN)'))

        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            technologies.append(('Generator', meta_generator['content']))

        links = soup.find_all('link')
        for link in links:
            href = link.get('href', '')
            if 'bootstrap' in href.lower():
                technologies.append(('Framework', 'Bootstrap (via CSS)'))
            elif 'font-awesome' in href.lower():
                technologies.append(('Library', 'Font Awesome (via CSS)'))

        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            if 'react' in src.lower():
                technologies.append(('Framework', 'React (via script)'))
            elif 'angular' in src.lower():
                technologies.append(('Framework', 'Angular (via script)'))
            elif 'vue' in src.lower():
                technologies.append(('Framework', 'Vue.js (via script)'))
            elif 'jquery' in src.lower():
                technologies.append(('Library', 'jQuery (via script)'))

        if 'php' in response.text.lower() and 'X-Powered-By' not in headers:
            technologies.append(('Language', 'PHP (detected in content)'))

        if '.asp' in response.text or '.aspx' in response.text:
            technologies.append(('Language', 'ASP.NET (detected in URLs)'))

        if '.jsp' in response.text or 'java' in server.lower():
            technologies.append(('Language', 'Java/JSP'))

        if 'ruby' in server.lower() or 'rails' in response.text.lower():
            technologies.append(('Language', 'Ruby on Rails'))

        if 'python' in server.lower() or 'django' in response.text.lower():
            technologies.append(('Language', 'Python/Django'))

        if 'express' in server.lower() or 'node' in server.lower():
            technologies.append(('Runtime', 'Node.js/Express'))

        technologies = list(set(technologies))
        technologies.sort(key=lambda x: x[0])

        if technologies:
            print(f"\n{Fore.GREEN}[✓] Detected Technologies:{Style.RESET_ALL}")
            for tech, value in technologies:
                print(f"   {Fore.CYAN}• {tech}:{Style.RESET_ALL} {value}")
        else:
            print(f"\n{Fore.YELLOW}[!] No specific technologies detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL INFORMATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}HTTP Headers Analysis:{Style.RESET_ALL}")
        print(f"   Status Code: {response.status_code}")
        print(f"   Content-Type: {headers.get('Content-Type', 'Not specified')}")
        print(f"   Server: {headers.get('Server', 'Not disclosed')}")

        content_length = len(response.content)
        print(f"   Page Size: {content_length} bytes ({content_length / 1024:.2f} KB)")

        if 'https' in target:
            print(f"{Fore.GREEN}   Connection: HTTPS (Secure){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}   Connection: HTTP (Not encrypted){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Technology detection completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")