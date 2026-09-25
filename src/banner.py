import socket


def get_banner(host, port, timeout=2):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        sock.connect((host, port))

        request = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"

        sock.sendall(request)

        response = sock.recv(1024)

        sock.close()

        return response.decode("utf-8", errors="ignore").strip()

    except Exception:
        return "No banner information available."