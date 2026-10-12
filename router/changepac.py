"""
  IP is whitelisted - the asset (packet untouched)
  else - the honeypot (change the destination IP)
Replies from the honeypot get the asset's IP as source, so the client never notices.
"""
import pickle
import socket
import threading

import pydivert

ASSET_IP = "192.168.1.20"  # real server
HP_IP = "192.168.1.30"     # honeypot
PORT = 5000                # web port of both servers
LISTEN_PORT = 9000         # the honeypot sends IPs to whitelist to this port
WHITELIST_FILE = "whitelist.pkl"

FILTER = (
    f"tcp and ((ip.DstAddr == {ASSET_IP} and tcp.DstPort == {PORT}) "
    f"or (ip.SrcAddr == {HP_IP} and tcp.SrcPort == {PORT}))"
)

# ---------- whitelist (saved in a pickle file) ----------
try:
    with open(WHITELIST_FILE, "rb") as f:
        whitelist = pickle.load(f)
except FileNotFoundError:
    whitelist = set()


def add_to_whitelist(ip):
    whitelist.add(ip)
    with open(WHITELIST_FILE, "wb") as f:
        pickle.dump(whitelist, f)
    print("whitelisted", ip)

#DEBUG
def listen_for_whitelist_requests():
    """The honeypot connects here and sends the IP of a client that logged in."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen()
    while True:
        conn, sender_ip = server.accept()
        ip = conn.recv(100).decode().strip()
        if sender_ip in (HP_IP, "127.0.0.1"):  # only the honeypot (or this computer)
            add_to_whitelist(ip)
        else:
            print("ignored whitelist request from", sender_ip)
        conn.close()

#packet routing

connections = {}  # (client_ip, client_port) -> "asset" or "hp"

def route_packets():
    with pydivert.WinDivert(FILTER, layer=pydivert.Layer.NETWORK_FORWARD) as w:
        for packet in w:
            if packet.src_addr == HP_IP:
                # honeypot -> client: pretend the reply comes from the asset
                packet.src_addr = ASSET_IP
            else:
                # client -> asset: choose the server once, when the connection starts,
                # so a connection never switches servers half-way
                client = (packet.src_addr, packet.src_port)
                if packet.tcp.syn and not packet.tcp.ack:
                    if packet.src_addr in whitelist:
                        connections[client] = "asset"
                    else:
                        connections[client] = "hp"
                    print(client, "->", connections[client])
                #NOT on whitelist -> redirect the packet to the HP
                if connections.get(client) == "hp":
                    packet.dst_addr = HP_IP
            w.send(packet)


if __name__ == "__main__":
    threading.Thread(target=listen_for_whitelist_requests, daemon=True).start()
    route_packets()