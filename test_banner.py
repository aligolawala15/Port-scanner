from src.banner import get_banner


host = "127.0.0.1"
port = 8000

banner = get_banner(host, port)

print("Banner:")
print(banner)