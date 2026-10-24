"""
Run as Administrator on the router (Windows):   python router.py

The asset and the honeypot run on the SAME computer, on different ports.
Clients always connect to REAL_PORT. For each new connection:
  - IP is whitelisted -> packet untouched (real site)
  - otherwise         -> destination port changed to HP_PORT (honeypot)
Replies from the honeypot get REAL_PORT as source port, so the client never notices.
"""
import pickle
import socket
import threading

import pydivert
from config import HP_PORT, LISTEN_PORT, REAL_PORT

SHOW_PACKETS = True  # True: print every diverted packet, False: only print new connections
WHITELIST_FILE = "whitelist.pkl"
FILTER = f"tcp and (tcp.DstPort == {REAL_PORT} or tcp.SrcPort == {HP_PORT})"

asset_ip = None  # filled in when the server computer announces itself

# ---------- whitelist (saved in a pickle file) ----------
try:
    with open(WHITELIST_FILE, "rb") as f:
        whitelist = pickle.load(f)
    print(f"loaded the whitelist: {len(whitelist)} IPs")
except FileNotFoundError:
    whitelist = set()
    print("no whitelist file yet, starting with an empty whitelist")
except EOFError:  # the file exists but is empty
    whitelist = set()
    print("the whitelist file is empty, starting with an empty whitelist")


def add_to_whitelist(ip):
    whitelist.add(ip)
    with open(WHITELIST_FILE, "wb") as f:
        pickle.dump(whitelist, f)
    print(f"whitelisted {ip} (the whitelist now has {len(whitelist)} IPs)")


# ---------- messages from the server computer ----------
def listen_for_messages():
    """  "ASSET"               -> the sender is the asset/honeypot computer
         "WHITELIST <ip>"      -> whitelist that client IP (only from the asset/HP computer or this computer)  """
    global asset_ip
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen()
    print(f"listening for messages from the server on port {LISTEN_PORT}")
    while True:
        conn, (sender_ip, _) = server.accept()
        try:
            parts = conn.recv(200).decode(errors="ignore").split()
        except OSError:
            parts = []
        conn.close()

        if parts == ["ASSET"]:
            asset_ip = sender_ip
            print(f"got the IP of the asset/HP computer: {asset_ip}")
            print(f"  real site = {asset_ip}:{REAL_PORT}, honeypot = {asset_ip}:{HP_PORT}")
        elif len(parts) == 2 and parts[0] == "WHITELIST":
            if sender_ip in (asset_ip, "127.0.0.1"):
                print(f"whitelist request from {sender_ip} for {parts[1]}")
                add_to_whitelist(parts[1])
            else:
                print(f"ignored a whitelist request from {sender_ip} (only the asset/HP computer may whitelist)")
        else:
            print(f"ignored an unknown message from {sender_ip}")


# ---------- packet routing ----------
connections = {}  # (client_ip, client_port) -> "asset" or "hp"


def route_packets():
    with pydivert.WinDivert(FILTER, layer=pydivert.Layer.NETWORK_FORWARD) as w:
        print("pydivert is open, waiting for packets (if nothing shows up, no packets reach this computer)...")
        for packet in w:
            if packet.dst_addr == asset_ip and packet.dst_port == REAL_PORT:
                # client -> asset: choose the server once, when the connection starts,
                # so a connection never switches servers half-way
                client = (packet.src_addr, packet.src_port)
                if packet.tcp.syn and not packet.tcp.ack:
                    if packet.src_addr in whitelist:
                        connections[client] = "asset"
                        print(f"new connection from {client[0]}:{client[1]} -> REAL SITE (whitelisted)")
                    else:
                        connections[client] = "hp"
                        print(f"new connection from {client[0]}:{client[1]} -> HONEYPOT (not whitelisted)")
                if connections.get(client) == "hp":
                    packet.tcp.dst_port = HP_PORT
                    if SHOW_PACKETS:
                        print(f"  diverted {client[0]}:{client[1]} -> {asset_ip}: port {REAL_PORT} changed to {HP_PORT}")

            elif packet.src_addr == asset_ip and packet.src_port == HP_PORT:
                # honeypot -> client: pretend the reply comes from the real port
                client = (packet.dst_addr, packet.dst_port)
                if connections.get(client) == "hp":
                    packet.tcp.src_port = REAL_PORT
                    if SHOW_PACKETS:
                        print(f"  reply {asset_ip} -> {client[0]}:{client[1]}: source port {HP_PORT} changed back to {REAL_PORT}")

            elif SHOW_PACKETS:
                print(f"  not diverted: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}"
                      f" (the asset/HP IP I know is {asset_ip})")

            w.send(packet)  # everything else goes through untouched


if __name__ == "__main__":
    threading.Thread(target=listen_for_messages, daemon=True).start()
    route_packets()