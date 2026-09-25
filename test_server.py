import socket

HOST = "127.0.0.1"
PORT = 8000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(5)

print(f"Test server running on {HOST}:{PORT}")
print("Keep this window open while testing the scanner.")

while True:
    client, address = server.accept()

    print(f"Connection received from {address}")

    client.sendall(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Port Scanner Test Server"
    )

    client.close()