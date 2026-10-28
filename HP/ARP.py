import socket

from config import ROUTER_IP, ROUTER_PORT


def whitelist_on_router(client_ip):
    with socket.create_connection((ROUTER_IP, ROUTER_PORT), timeout=3) as s:
        s.sendall(f"WHITELIST {client_ip}".encode())
    print(f"asked the router to whitelist {client_ip}")