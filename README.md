# VulEye — Ethical Security Scanner Suite

**Unified toolkit for authorized vulnerability assessment and security testing.**  
*Use responsibly. Unauthorized scanning = criminal offense.*

---

## ⚠️ CRITICAL ETHICAL WARNING

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY.**

❌ **NEVER USE WITHOUT EXPLICIT WRITTEN PERMISSION:**
- Public websites or services you don't own
- Corporate networks without signed authorization
- Cloud infrastructure (AWS/Azure/GCP) without owner consent
- Any system where you cannot prove legal authorization

✅ **AUTHORIZED USE CASES ONLY:**
- Your own systems and virtual machines
- Legitimate penetration testing with signed contract
- Educational labs (DVWA, Juice Shop, Metasploitable)
- Platforms with explicit testing policies (HackTheBox, TryHackMe)

> ⚖️ **Legal Notice:** Unauthorized scanning violates:
> - Computer Fraud and Abuse Act (USA)
> - Article 272/273 of Criminal Code (Russia)
> - Computer Misuse Act (UK)
> - GDPR Article 32 (EU)
> 
> **You are solely responsible for your actions.** This tool includes ethical warnings but does not protect you from prosecution.

## Installation




# Project Name

Brief description of your project here.

## Installation

```
BASH
```
1. Clone the repository:
```
git clone https://github.com/Kyni-lover2004/VulEye
cd VulEye
```
3. Install the required Python packages:
```
pip install -r requirements.txt
```
4. Usage
```
chmod +x main.py
python3 main.py
```



---

## 🎯 Project Overview

VulEye is a **unified security testing toolkit** designed for ethical penetration testers and security researchers. It provides:

- ✅ **15+ vulnerability scanners** (web, network, auth, config)
- ✅ **Automated technology detection** (CMS, frameworks, servers)
- ✅ **Comprehensive security headers analysis**
- ✅ **SSL/TLS configuration assessment**
- ✅ **Exposed files and directories discovery**
- ✅ **Educational CVE database** (templates with legal warnings)
- ✅ **Single-menu interface** — no complex CLI arguments
- ✅ **Automatic report generation** in `reports/` directory
- ✅ **Built-in ethical safeguards** — mandatory permission confirmation

**Philosophy:** Security tools should empower defenders, not enable attackers. Every module requires explicit ethical confirmation before execution.

---

## 📂 Project Structure

```
VulEye/
├── main.py                # Unified menu interface
├── reports/               # Auto-generated security reports (JSON/TXT)
├── core/
│   ├── server_did.py  
│   ├── web_analysts.py 
│   └── help.py            # Complete usage guide & legal warnings
├── modules/
│   ├── web/               # Web application vulnerabilities
│   │   ├── sqli.py        # SQL Injection scanner
│   │   ├── xss.py         # Cross-Site Scripting scanner
│   │   ├── lfi.py         # Local File Inclusion scanner
│   │   ├── ssrf.py        # Server-Side Request Forgery scanner
│   │   ├── xxe.py         # XML External Entity scanner
│   │   ├── cors.py        # CORS misconfiguration scanner
│   │   ├── redirect.py    # Open Redirect scanner
│   │   ├── csrf.py        # CSRF protection analyzer
│   │   ├── file_upload.py # Insecure file upload scanner
│   │   └── ...            # Additional web modules
│   ├── network/           # Network vulnerabilities
│   │   ├── port_scan.py   # TCP/UDP port scanner
│   │   ├── subdomain_enum.py  # Subdomain enumeration
│   │   ├── dns_enum.py    # DNS enumeration & zone transfer test
│   │   └── smb_enum.py    # SMB share enumeration
│   ├── auth/              # Authentication vulnerabilities
│   │   ├── brute.py       # Credential brute-forcing (safe mode)
│   │   ├── idor.py        # Insecure Direct Object Reference scanner
│   │   ├── rate_limit.py  # Brute-force protection analyzer
│   │   └── default_creds.py  # Default credentials checker
│   ├── config/            # Configuration vulnerabilities
│   │   ├── headers.py     # Security headers analyzer
│   │   ├── exposed.py     # Exposed sensitive files scanner
│   │   ├── dir_listing.py # Open directory listing checker
│   │   ├── error_disclosure.py  # Error message disclosure scanner
│   │   ├── cookie_check.py      # Cookie security attributes analyzer
│   │   └── http_methods.py      # Dangerous HTTP methods scanner
│   └── info/              # Information gathering
│       ├── tech_detect.py # Technology stack fingerprinting
│       ├── cms_detect.py  # CMS/framework detection
│       ├── ssl_check.py   # SSL/TLS configuration analyzer
│       └── cert_info.py   # Certificate details analyzer
└── payloads/              # Educational CVE templates (NOT working exploits)
  
```

**Why this structure?**
- All modules work through unified menu (`main.py`)
- `core/` contains shared utilities (currently only `help.py`)
- `payloads/` contains **educational templates only** — not working exploits
- Each module has mandatory ethical confirmation before execution

---

## 🚀 Quick Start Guide

### Basic Usage
```bash
# Launch the unified menu
python3 main.py
```

### Menu Navigation
```
VulEye — MAIN MENU
======================================================================
 1. Modules          → vulnerability scanners by category
 2. Core Tools       → help system and utilities
 3. Exploits Database → CVE-indexed educational templates
 0. Exit
======================================================================
Select option [0-3]: 1

MODULES CATEGORIES
======================================================================
 1. Web
 2. Network
 3. Auth
 4. Config
 5. Info
 0. Back to main menu
======================================================================
Select category [0-5]: 1

Available modules in web category:
----------------------------------------------------------------------
 1. cors
 2. csrf
 3. file_upload
 4. lfi
 5. redirect
 6. sqli
 7. ssrf
 8. xss
 0. Back to categories
----------------------------------------------------------------------
Select module [0-8]: 8

[+] Running xss (web)...
----------------------------------------------------------------------

⚠️  ETHICAL WARNING
   Use ONLY on systems you own or have written permission to test.
Confirm ethical use? (yes/no): yes

Enter target URL (e.g., http://site.com/search?q=test): http://localhost/vulnerable
[+] Analyzing for XSS vulnerabilities...
[✓] Test completed. No obvious XSS vulnerabilities detected.
```

### Example Workflows
| Scenario | Steps |
|----------|-------|
| **Quick security assessment** | `1 → Info → tech_detect.py` → `1 → Config → headers.py` → `1 → Config → exposed.py` |
| **Web app penetration test** | `1 → Web → sqli.py` → `1 → Web → xss.py` → `1 → Web → lfi.py` → `1 → Web → ssrf.py` |
| **Network reconnaissance** | `1 → Network → port_scan.py` → `1 → Network → subdomain_enum.py` → `1 → Network → dns_enum.py` |
| **Authentication audit** | `1 → Auth → rate_limit.py` → `1 → Auth → default_creds.py` → `1 → Auth → idor.py` |
| **Full site analysis** | `1 → Web → comprehensive_scan.py` (all-in-one scanner) |

---

## ⚖️ Legal Protection Guidelines

### Before ANY Testing Activity:
1. **Obtain written authorization** signed by system owner
   - Template: [OWASP Authorization Letter](https://owasp.org/www-pdf-archive/OWASP_Authorization_Letter.pdf)
2. **Document scope explicitly:**
   - IP ranges/domains authorized for testing
   - Allowed techniques and time windows
   - Prohibited actions (e.g., "no DoS testing")
3. **Save evidence of authorization:**
   - Screenshots of signed documents
   - Email confirmations with timestamps
   - Contract excerpts (redact sensitive info)

### During Testing:
- All scans **automatically save reports** to `reports/` directory
- Never access or exfiltrate sensitive data without explicit permission
- Immediately stop if you discover unexpected critical systems
- Document all actions with timestamps

### After Testing:
- Maintain records for **minimum 12 months**
- Provide professional report to system owner
- Never disclose vulnerabilities publicly without coordination
- Follow responsible disclosure guidelines: [CERT/CC](https://www.cert.org/vulnerability-analysis/vul-disclosure.cfm)

> 🔒 **Critical Reminder:** Ethical warnings in this tool do NOT protect you from prosecution. Only documented authorization provides legal defense.

---

## 🛡️ Safe Testing Environments (100% Legal)

**NEVER test on production systems without authorization.** Use these legal alternatives:

### Docker Vulnerable Applications (Recommended)
```bash
# Damn Vulnerable Web App (DVWA)
docker run -p 80:80 vulnerables/web-dvwa

# OWASP Juice Shop (modern vulnerable app)
docker run -p 3000:3000 bkimminich/juice-shop

# Vulnerable WordPress
docker run -p 8080:8080 vulnerables/wordpress

# Apache Struts RCE (CVE-2017-5638)
docker run -p 8080:8080 vulhub/struts2/s2-045
```

### Virtual Machines (VulnHub)
- [Metasploitable 2/3](https://sourceforge.net/projects/metasploitable/) — Classic vulnerable VM
- [Kioptrix Series](https://www.vulnhub.com/series/kioptrix,23/) — Beginner-friendly challenges
- [DC Series](https://www.vulnhub.com/series/dc,48/) — Realistic scenarios
- [Download all](https://www.vulnhub.com) — 100+ free vulnerable machines

### Training Platforms
- [TryHackMe](https://tryhackme.com) — Beginner-friendly (free tier available)
- [HackTheBox](https://www.hackthebox.com) — Advanced challenges (free tier available)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — XSS/SQLi labs

---

## ➕ Adding New Modules

### Step-by-Step Guide
1. **Create module file** in appropriate category:
   ```bash
   touch modules/web/my_new_scanner.py
   ```

2. **Implement mandatory `run()` function** with ethical confirmation:
   ```python
   # modules/web/my_new_scanner.py
   from colorama import init, Fore, Style
   init(autoreset=True)
   
   def run():
       print(f"\n{Fore.CYAN}{'='*70}")
       print(f"{Fore.CYAN}║{Fore.GREEN}              MY NEW SCANNER                                      {Fore.CYAN}║")
       print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
       
       print(f"\n{Fore.YELLOW}⚠️  ETHICAL WARNING{Style.RESET_ALL}")
       print(f"   Use ONLY on systems you own or have written permission to test.")
       confirm = input("Confirm ethical use? (yes/no): ").strip().lower()
       if confirm != "yes":
           print(f"\n{Fore.RED}[!] Operation aborted by user.{Style.RESET_ALL}")
           input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
           return
       
       # Your scanner logic here
       target = input(f"\n{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}").strip()
       # ... scanning code ...
       
       input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
   ```

3. **Restart VulEye** — module appears automatically in menu (no configuration needed)

### Critical Requirements for All Modules
✅ Must include ethical warning before execution  
✅ Must require explicit "yes" confirmation  
✅ Must save results to `reports/` directory  
✅ Must handle exceptions gracefully (no crashes)  
✅ Must include timeout protection (max 15 seconds per request)  
✅ Must avoid aggressive payloads without user confirmation  

---

## ❓ Frequently Asked Questions

**Q: Can I use this on real websites to "help" them find vulnerabilities?**  
A: **NO.** "Helping" without authorization = illegal hacking. Always get written permission first. Responsible disclosure requires authorization BEFORE testing.

**Q: Why doesn't `payloads/` contain working exploits?**  
A: To protect users from legal liability. All files are **educational templates only** with:
- Legal warnings in every file header
- Links to legitimate sources (Exploit-DB, GitHub educational repos)
- Instructions for legal testing environments only

**Q: How do I verify a vulnerability is real before reporting?**  
A:  
1. Reproduce in isolated environment (Docker/VulnHub)  
2. Document with screenshots and request/response logs  
3. Never access sensitive data during verification  
4. Use read-only tests only (no data modification)  
5. Consult [CERT/CC Vulnerability Disclosure Guidelines](https://www.cert.org/vulnerability-analysis/vul-disclosure.cfm)

**Q: What if I accidentally find a vulnerability on a system I don't own?**  
A:  
1. **STOP immediately** — do not investigate further  
2. Do not access any additional data  
3. Contact owner through official security contact (security@domain.com)  
4. Provide only minimal information to verify ownership  
5. Follow their disclosure process  

**Q: Is this tool legal to possess/download?**  
A: Generally yes (like owning lockpicks), BUT:
- Possession ≠ authorization to use
- Using without permission = illegal regardless of tool legality
- Some jurisdictions restrict security tools (check local laws)
- Always maintain proof of authorization for ANY testing

---

## 📜 License

```
VulEye — Ethical Security Scanner Suite
Copyright (C) 2024 [Your Name]

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

> ⚠️ **Critical License Note:**  
> The GPL license covers SOFTWARE DISTRIBUTION ONLY. It does **NOT**:
> - Grant permission to test unauthorized systems
> - Protect you from criminal prosecution for unauthorized access
> - Override local computer crime laws
> 
> **You remain solely responsible for legal compliance during usage.**

---

## 🙏 Acknowledgements

- **OWASP** — Security testing methodologies and guidelines
- **VulnHub** — Free vulnerable virtual machines for education
- **Exploit-DB** — Public vulnerability database (educational use only)
- **Nmap Security Scanner** — Inspiration for ethical scanning approach
- **Metasploit Framework** — Reference for responsible vulnerability disclosure
- **All security researchers** who prioritize defense over offense

---

## 📬 Support & Contributions

**Issues/Feature Requests:**  
→ [GitHub Issues](https://github.com/yourusername/VulEye/issues)  
*Please include: OS, Python version, error logs, and reproduction steps*

**Contributing Modules:**  
1. Fork repository
2. Create module following [Adding New Modules](#-adding-new-modules) guide
3. Ensure ethical safeguards are implemented
4. Submit pull request with description of functionality
5. All contributions require explicit ethical use confirmation

**⚠️ Contribution Policy:**  
- No working exploits without legal educational context
- All modules must include ethical warnings
- No modules targeting specific organizations/products without permission
- Maintainers reserve right to reject modules lacking ethical safeguards

---

## 🔒 Final Ethical Reminder

> *"With great power comes great responsibility."*  
> — Voltaire (often misattributed to Spider-Man)

This tool empowers security professionals to **strengthen defenses**, not compromise systems. Every scan must be:
- ✅ Authorized in writing
- ✅ Limited to agreed scope
- ✅ Documented for legal protection
- ✅ Reported responsibly to owners

**When in doubt: DON'T SCAN.**  
Obtain explicit permission first. Your freedom depends on it.

---

*VulEye — Making security testing ethical, educational, and effective.*  
*Version 1.0 • © 2024 [Kyni-lover2004] • GPL-3.0 Licensed*


cd ..
python3 VulEye/main.py
