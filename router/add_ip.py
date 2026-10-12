import socket
import sys
# this is a tool for me to check it works...
# Whitelist an IP by hand while changepac.py is running
with socket.create_connection(("127.0.0.1", 9000)) as s:
    s.sendall(sys.argv[1].encode())
print("sent", sys.argv[1])