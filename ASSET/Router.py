"""
Run as Administrator, on the SAME computer as the asset:   python router.py

Clients send straight to this computer's own IP (ASSET_IP), so traffic always
arrives here - no routing tricks needed to "catch" it. For a NEW connection:
  - IP is whitelisted -> the packet is left alone, and reaches the asset app
                          running locally on this computer.
  - otherwise         -> the packet is redirected to the honeypot computer
                          (HP_IP), with the source address changed to ASSET_IP
                          so the honeypot's replies come back through here too.
That reply then gets its source address changed back to ASSET_IP's own address
before being sent on to the client, so the client never notices the honeypot.
"""
import pickle
import socket
import threading

import pydivert
from config import ASSET_IP, HP_IP, LISTEN_PORT, PORT

WHITELIST_FILE = "whitelist.pkl"

# only genuinely NEW network traffic is captured - never our own redirected packets,
# which avoids the router catching and re-processing its own output
FILTER = (
    f"inbound and ip.DstAddr == {ASSET_IP} and tcp.DstPort == {PORT}"
    f" or inbound and ip.SrcAddr == {HP_IP} and tcp.SrcPort == {PORT}"
)

connections = {}     # client_ip -> "asset" or "hp", re-checked on every new connection from that IP
client_ip_of = {}    # client_port -> client_ip, so a honeypot reply can be sent to the right client
seen_ports = set()   # (client_ip, client_port) already printed, so a retransmitted SYN isn't printed twice

# ---------- whitelist (saved in a pickle file) ----------
try:
    with open(WHITELIST_FILE, "rb") as f:
        whitelist = pickle.load(f)
    print(f"loaded the whitelist: {len(whitelist)} IPs")
except (FileNotFoundError, EOFError):
    whitelist = set()
    print("no whitelist yet, starting with an empty one")


def add_to_whitelist(ip):
    whitelist.add(ip)
    with open(WHITELIST_FILE, "wb") as f:
        pickle.dump(whitelist, f)
    print(f"whitelisted {ip} (the whitelist now has {len(whitelist)} IPs)")


# ---------- whitelist requests from the honeypot computer ----------
def listen_for_messages():
    """The honeypot sends "WHITELIST <ip>" here after a real login."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen()
    print(f"listening for whitelist requests on port {LISTEN_PORT}")
    while True:
        conn, (sender_ip, _) = server.accept()
        try:
            parts = conn.recv(200).decode(errors="ignore").split()
        except OSError:
            parts = []
        conn.close()

        if sender_ip in (HP_IP, "127.0.0.1") and len(parts) == 2 and parts[0] == "WHITELIST":
            print(f"whitelist request from {sender_ip} for {parts[1]}")
            add_to_whitelist(parts[1])
        else:
            print(f"ignored a message from {sender_ip}")


# ---------- packet routing ----------
def route_packets():
    print(f"asset = {ASSET_IP}:{PORT}, honeypot = {HP_IP}:{PORT}")
    with pydivert.WinDivert(FILTER, layer=pydivert.Layer.NETWORK) as w:
        print("pydivert is open, waiting for packets (if nothing shows up, no packets reach this computer)...")
        for packet in w:

            if packet.dst_addr == ASSET_IP and packet.dst_port == PORT:
                # a client's packet, addressed to the asset on this computer
                client_ip = packet.src_addr

                if packet.tcp.syn and not packet.tcp.ack:  # a new connection: always re-check the whitelist,
                    target = "asset" if client_ip in whitelist else "hp"  # in case this IP just got whitelisted
                    connections[client_ip] = target
                    client_ip_of[packet.src_port] = client_ip

                    port_key = (client_ip, packet.src_port)
                    if port_key[0] not in [ip[0] for ip in seen_ports]:  # print once per connection, not on every retransmitted SYN
                        seen_ports.add(port_key)
                        print(f"new connection from {client_ip} -> {'REAL SITE' if target == 'asset' else 'HONEYPOT'}")

                if connections.get(client_ip) == "hp":
                    packet.dst_addr = HP_IP        # send it to the honeypot instead
                    packet.src_addr = ASSET_IP     # pretend it came from us, so the reply returns here
                    packet.recalculate_checksums()  # addresses changed, so the old checksum is now wrong
                # whitelisted clients: packet is left exactly as it is, and reaches the local asset app

            elif packet.src_addr == HP_IP and packet.src_port == PORT:
                # a reply from the honeypot, meant for one of our clients
                client_ip = client_ip_of.get(packet.dst_port)
                if client_ip:
                    packet.dst_addr = client_ip    # send it on to the real client
                    packet.src_addr = ASSET_IP     # pretend the reply came from the asset, not the honeypot
                    packet.recalculate_checksums()  # addresses changed, so the old checksum is now wrong

            w.send(packet)


if __name__ == "__main__":
    threading.Thread(target=listen_for_messages, daemon=True).start()
    route_packets()