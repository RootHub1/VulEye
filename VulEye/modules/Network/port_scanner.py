import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)


WELL_KNOWN_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def scan_port(ip, port, timeout=1.0):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = WELL_KNOWN_PORTS.get(port, "Unknown")
            return (port, "OPEN", service)
    except:
        pass
    return None


def get_port_range():
    print(f"\n{Fore.CYAN}Select port range to scan:{Style.RESET_ALL}")
    print(f"   1. Top 100 ports (fastest)")
    print(f"   2. Top 1000 ports (recommended)")
    print(f"   3. All ports 1-65535 (comprehensive, slow)")
    print(f"   4. Custom range (e.g., 8000-9000)")

    choice = input(f"\n{Fore.YELLOW}Select option [1-4]: {Style.RESET_ALL}").strip()

    if choice == "1":
        return list(range(1, 101))
    elif choice == "2":
        return list(range(1, 1001))
    elif choice == "3":
        return list(range(1, 65536))
    elif choice == "4":
        custom = input(f"{Fore.YELLOW}Enter port range (e.g., 8000-9000): {Style.RESET_ALL}").strip()
        try:
            start, end = map(int, custom.split('-'))
            if 1 <= start <= end <= 65535:
                return list(range(start, end + 1))
            else:
                print(f"{Fore.RED}[!] Invalid port range. Using default 1-1000.{Style.RESET_ALL}")
                return list(range(1, 1001))
        except:
            print(f"{Fore.RED}[!] Invalid format. Using default 1-1000.{Style.RESET_ALL}")
            return list(range(1, 1001))
    else:
        print(f"{Fore.YELLOW}[i] Invalid choice. Using default 1-1000.{Style.RESET_ALL}")
        return list(range(1, 1001))


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              POWERFUL PORT SCANNER                                {Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.GREEN}          Scans 1-65535 ports • Shows ONLY open ports              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")


    target = input(f"\n{Fore.YELLOW}Enter target IP address (e.g., 192.168.1.100): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return


    if not is_valid_ip(target):
        print(f"\n{Fore.RED}[!] Invalid IP address format.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return


    ports = get_port_range()
    total_ports = len(ports)


    print(f"\n{Fore.CYAN}Select scan speed:{Style.RESET_ALL}")
    print(f"   1. Aggressive (1000 threads) - Fastest but may miss ports")
    print(f"   2. Balanced (500 threads) - Recommended")
    print(f"   3. Stealthy (100 threads) - Slower but more reliable")

    speed_choice = input(f"\n{Fore.YELLOW}Select option [1-3]: {Style.RESET_ALL}").strip()
    threads = 1000 if speed_choice == "1" else (500 if speed_choice == "2" else 100)


    timeout = 0.3 if speed_choice == "1" else (0.5 if speed_choice == "2" else 1.0)

    print(f"\n{Fore.CYAN}[+] Starting scan on {target} ({total_ports} ports, {threads} threads){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Showing ONLY open ports in real-time{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    start_time = time.time()
    open_ports = []
    scanned = 0
    last_update = time.time()


    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, target, port, timeout): port for port in ports}

        for future in as_completed(futures):
            result = future.result()
            scanned += 1


            current_time = time.time()
            if current_time - last_update > 5:
                percent = (scanned / total_ports) * 100
                print(f"{Fore.CYAN}[→] Scanned {scanned}/{total_ports} ports ({percent:.1f}%)...{Style.RESET_ALL}")
                last_update = current_time

            if result:
                port, status, service = result
                open_ports.append(result)
                print(f"{Fore.GREEN}[✓] Port {port:5d}/tcp  OPEN  →  {service}{Style.RESET_ALL}")

    end_time = time.time()
    duration = end_time - start_time


    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SCAN COMPLETE")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Target: {target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Duration: {duration:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Ports scanned: {total_ports}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Open ports found: {len(open_ports)}{Style.RESET_ALL}")

    if open_ports:
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}OPEN PORTS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        for port, status, service in sorted(open_ports):
            service_color = Fore.MAGENTA if port in [22, 3389, 5900] else (
                Fore.RED if port in [21, 23, 135, 139, 445] else Fore.YELLOW)
            print(f"{Fore.GREEN}PORT {port:5d}/tcp{Style.RESET_ALL}  {service_color}{service}{Style.RESET_ALL}")


            if port == 22:
                print(f"   {Fore.CYAN}→ SSH service - check for weak credentials{Style.RESET_ALL}")
            elif port == 21:
                print(f"   {Fore.RED}→ FTP service - often has anonymous access{Style.RESET_ALL}")
            elif port == 23:
                print(f"   {Fore.RED}→ Telnet service - credentials transmitted in plaintext{Style.RESET_ALL}")
            elif port in [135, 139, 445]:
                print(f"   {Fore.RED}→ SMB service - check for EternalBlue (MS17-010){Style.RESET_ALL}")
            elif port == 3389:
                print(f"   {Fore.CYAN}→ RDP service - check for BlueKeep (CVE-2019-0708){Style.RESET_ALL}")
            elif port == 3306:
                print(f"   {Fore.YELLOW}→ MySQL service - check for weak root password{Style.RESET_ALL}")
            elif port == 6379:
                print(f"   {Fore.RED}→ Redis service - often unauthenticated{Style.RESET_ALL}")


        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}NEXT STEPS FOR VULNERABILITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        smb_ports = [p for p, s, svc in open_ports if p in [135, 139, 445]]
        if smb_ports:
            print(f"{Fore.RED}⚠️  SMB Ports Open ({', '.join(map(str, smb_ports))}){Style.RESET_ALL}")
            print(f"   → Run: Modules → Network → smb_enum")
            print(f"   → Check for EternalBlue (CVE-2017-0144)")
            print(f"   → Test for SMB signing bypass")

        ssh_port = [p for p, s, svc in open_ports if p == 22]
        if ssh_port:
            print(f"{Fore.CYAN}⚠️  SSH Port Open (22){Style.RESET_ALL}")
            print(f"   → Run: Modules → Auth → brute (for SSH brute-force testing)")
            print(f"   → Check for weak key exchange algorithms")

        http_ports = [p for p, s, svc in open_ports if p in [80, 443, 8080, 8443]]
        if http_ports:
            print(f"{Fore.YELLOW}⚠️  Web Ports Open ({', '.join(map(str, http_ports))}){Style.RESET_ALL}")
            print(f"   → Run: Modules → Web → comprehensive_scan")
            print(f"   → Test for web application vulnerabilities (SQLi, XSS, LFI)")

        db_ports = [p for p, s, svc in open_ports if p in [3306, 5432, 27017, 1521, 1433]]
        if db_ports:
            print(f"{Fore.RED}⚠️  Database Ports Open ({', '.join(map(str, db_ports))}){Style.RESET_ALL}")
            print(f"   → Check for default credentials")
            print(f"   → Verify network isolation")
    else:
        print(f"\n{Fore.GREEN}[✓] No open ports found.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Target may be firewalled or offline.{Style.RESET_ALL}")


    save = input(
        f"\n{Fore.YELLOW}Save report to reports/portscan_{target.replace('.', '_')}.txt? (yes/no): {Style.RESET_ALL}").strip().lower()
    if save == "yes":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/portscan_{target.replace('.', '_')}_{timestamp}.txt"
        try:
            with open(filename, 'w') as f:
                f.write("=" * 70 + "\n")
                f.write("POWERFUL PORT SCANNER — REPORT\n")
                f.write("=" * 70 + "\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Ports scanned: {total_ports}\n")
                f.write(f"Threads: {threads}\n")
                f.write(f"Timeout: {timeout} seconds\n")
                f.write("=" * 70 + "\n\n")

                if open_ports:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 70 + "\n")
                    for port, status, service in sorted(open_ports):
                        f.write(f"Port {port:5d}/tcp  OPEN  →  {service}\n")
                    f.write("\n" + "=" * 70 + "\n")
                    f.write("NEXT STEPS:\n")
                    f.write("=" * 70 + "\n")
                    if smb_ports:
                        f.write(f"• SMB Ports ({', '.join(map(str, smb_ports))}) → Test for EternalBlue\n")
                    if ssh_port:
                        f.write(f"• SSH Port (22) → Test for weak credentials\n")
                    if http_ports:
                        f.write(f"• Web Ports ({', '.join(map(str, http_ports))}) → Run web vulnerability scan\n")
                    if db_ports:
                        f.write(f"• Database Ports ({', '.join(map(str, db_ports))}) → Check default credentials\n")
                else:
                    f.write("No open ports found.\n")

            print(f"\n{Fore.GREEN}[✓] Report saved: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error saving report: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Port scan completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}  LEGAL REMINDER:{Style.RESET_ALL}")
    print(f"   Port scanning without authorization is illegal in most jurisdictions.")
    print(f"   Always obtain written permission before scanning any system.")
    print(f"   Maintain logs of authorized scanning activities for legal protection.")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback

        traceback.print_exc()
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")