import socket
import sys

from config import LISTEN_PORT

# Whitelist an IP by hand while router.py is running:   python add_ip.py 192.168.1.50
with socket.create_connection(("127.0.0.1", LISTEN_PORT)) as s:
    s.sendall(f"WHITELIST {sys.argv[1]}".encode())
print("sent", sys.argv[1])