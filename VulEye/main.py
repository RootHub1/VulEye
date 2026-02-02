import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules import BrutePass, PayScan, SQLiEye, xssEye


def show_banner():
    print("""
╔════════════════════════════════════════════════════════╗
║              VulEye — Unified Interface                ║
║            All your tools in one place                 ║
╚════════════════════════════════════════════════════════╝
""")


def show_menu():
    print("\n" + "=" * 50)
    print(" MENU:")
    print("=" * 50)
    print("  1. Port Scanner        (PayScan)")
    print("  2. SQL Injection check (SQLiEye)")
    print("  3. XSS check           (xssEye)")
    print("  4. BruteForce          (BrutePass)")
    print("  0. EXIT")
    print("=" * 50)
    return input("\nEnter tool [0-4]: ").strip()


def main():
    show_banner()

    while True:
        choice = show_menu()

        try:
            if choice == "1":
                PayScan.run()

            elif choice == "2":
                SQLiEye.run()

            elif choice == "3":
                xssEye.run()

            elif choice == "4":
                BrutePass.run()

            elif choice == "0":
                print("\n Goodbye! Remember: ethics first.\n")
                break

            else:
                print("\n Incorrect selection. Try again.")

        except Exception as e:
            print(f"\n[!] Tool error: {e}")

        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n Interrupted by user. Exiting...")
        sys.exit(0)
