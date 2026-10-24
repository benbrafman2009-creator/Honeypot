import socket

from config import ROUTER_IP, ROUTER_PORT


def send_to_router(message):
    with socket.create_connection((ROUTER_IP, ROUTER_PORT), timeout=3) as s:
        s.sendall(message.encode())


def announce_to_router():
    """Tell the router we exist. It reads our IP from the connection itself."""
    send_to_router("ASSET")
    print(f"announced this computer to the router at {ROUTER_IP}:{ROUTER_PORT}")


def whitelist_on_router(client_ip):
    send_to_router(f"WHITELIST {client_ip}")
    print(f"asked the router to whitelist {client_ip}")


if __name__ == "__main__":
    announce_to_router()