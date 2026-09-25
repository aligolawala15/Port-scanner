import socket
import re
from datetime import datetime
from services import get_service_name


# --------------------------------------------------
# Get hostname from user
# --------------------------------------------------

def clean_target(target):
    """
    Convert a website URL into a hostname.

    Example:
    https://example.com → example.com
    http://example.com → example.com
    example.com → example.com
    """

    target = target.strip()

    # Remove protocol
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)

    # Remove path
    target = target.split("/")[0]

    # Remove port if user enters one
    target = target.split(":")[0]

    return target


# --------------------------------------------------
# Find IP address
# --------------------------------------------------

def get_ip_address(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address

    except socket.gaierror:
        return None


# --------------------------------------------------
# Check a single port
# --------------------------------------------------

def scan_port(hostname, port, timeout=0.2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Don't wait forever
        sock.settimeout(timeout)

        result = sock.connect_ex((hostname, port))

        sock.close()

        if result == 0:
            return True

        return False

    except socket.error:
        return False


# --------------------------------------------------
# Scan multiple ports
# --------------------------------------------------

def scan_ports(hostname, start_port, end_port):

    open_ports = []

    print()
    print("Starting scan...")
    print("-" * 60)

    for port in range(start_port, end_port + 1):

        is_open = scan_port(hostname, port)

        if is_open:
            service = get_service_name(port)

            print(
                f"[+] Port {port:<5} OPEN       Service: {service}"
            )

            open_ports.append({
                "port": port,
                "service": service
            })

    print("-" * 60)

    return open_ports


# --------------------------------------------------
# Save scan report
# --------------------------------------------------

def save_report(hostname, ip_address, open_ports):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"reports/scan_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as file:

        file.write("WEBSITE PORT SCANNER REPORT\n")
        file.write("=" * 50 + "\n")

        file.write(f"Target: {hostname}\n")
        file.write(f"IP Address: {ip_address}\n")
        file.write(
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        file.write("\nOPEN PORTS\n")
        file.write("-" * 50 + "\n")

        if not open_ports:
            file.write("No open ports found.\n")

        else:
            for item in open_ports:

                file.write(
                    f"Port: {item['port']} | "
                    f"Service: {item['service']}\n"
                )

    return filename


# --------------------------------------------------
# Main program
# --------------------------------------------------

def main():

    print("=" * 60)
    print("              WEBSITE PORT SCANNER")
    print("=" * 60)

    print()
    print("Use this scanner only on systems you are")
    print("authorized to test.")
    print()

    target = input("Enter website or hostname: ")

    hostname = clean_target(target)

    if not hostname:
        print("[!] Invalid target.")
        return

    print()
    print(f"Target: {hostname}")

    # Find IP
    ip_address = get_ip_address(hostname)

    if ip_address is None:
        print("[!] Could not resolve the hostname.")
        return

    print(f"IP Address: {ip_address}")

    # Port range
    try:

        start_port = int(
            input("Enter starting port (default 1): ") or "1"
        )

        end_port = int(
            input("Enter ending port (default 1024): ") or "1024"
        )

    except ValueError:

        print("[!] Port must be a number.")
        return

    # Validate ports
    if start_port < 1 or end_port > 65535:
        print("[!] Ports must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("[!] Starting port cannot be greater than ending port.")
        return

    print()
    print(f"Scanning {hostname}")
    print(f"Ports: {start_port} - {end_port}")

    # Start scan
    open_ports = scan_ports(
        hostname,
        start_port,
        end_port
    )

    # Results
    print()
    print("SCAN COMPLETED")
    print("=" * 60)

    if open_ports:

        print(f"Open ports found: {len(open_ports)}")
        print()

        for item in open_ports:
            print(
                f"Port {item['port']} → {item['service']}"
            )

    else:

        print("No open ports found.")

    # Save report
    report_file = save_report(
        hostname,
        ip_address,
        open_ports
    )

    print()
    print(f"Report saved to: {report_file}")


# --------------------------------------------------
# Run program
# --------------------------------------------------

if __name__ == "__main__":
    main()