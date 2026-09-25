import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((host, port))

        sock.close()

        if result == 0:
            return port

    except socket.error:
        pass

    return None


def scan_ports(host, start_port, end_port, workers=100):

    open_ports = []

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }

        for future in as_completed(futures):

            result = future.result()

            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)


if __name__ == "__main__":

    target = input("Enter target: ")

    try:
        ip = socket.gethostbyname(target)

        print(f"\nTarget: {target}")
        print(f"IP Address: {ip}")

        start = int(input("Start port: "))
        end = int(input("End port: "))

        print("\nScanning...\n")

        ports = scan_ports(ip, start, end)

        if ports:
            print("OPEN PORTS")

            for port in ports:
                print(f"[+] {port}")

        else:
            print("No open ports found.")

    except socket.gaierror:
        print("[!] Could not resolve hostname.")

    except ValueError:
        print("[!] Port must be a number.")