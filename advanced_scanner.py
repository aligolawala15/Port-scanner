import socket

from src.scanner import scan_ports
from src.services import get_service_name
from src.reporter import save_json, save_csv
from src.database import create_database, save_scan


def main():

    print("=" * 60)
    print("        ADVANCED PYTHON PORT SCANNER")
    print("=" * 60)

    print()
    print("Only scan systems you are authorized to test.")
    print()

    target = input("Enter target: ").strip()

    try:
        ip = socket.gethostbyname(target)

    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    print(f"\nTarget: {target}")
    print(f"IP Address: {ip}")

    try:

        start = int(
            input("Start port: ")
        )

        end = int(
            input("End port: ")
        )

    except ValueError:

        print("[!] Invalid port.")
        return

    if start < 1 or end > 65535 or start > end:

        print("[!] Invalid port range.")
        return

    print("\nScanning...")
    print("-" * 60)

    open_ports = scan_ports(
        ip,
        start,
        end
    )

    if not open_ports:

        print("No open ports found.")

        return

    print("\nOPEN PORTS")
    print("-" * 60)

    for port in open_ports:

        service = get_service_name(port)

        print(
            f"[+] {port:<5} "
            f"{service}"
        )

    create_database()

    save_scan(
        target,
        ip,
        open_ports
    )

    json_file = save_json(
        target,
        ip,
        open_ports
    )

    csv_file = save_csv(
        target,
        ip,
        open_ports
    )

    print("\nScan completed.")

    print(f"JSON report: {json_file}")
    print(f"CSV report: {csv_file}")


if __name__ == "__main__":
    main()