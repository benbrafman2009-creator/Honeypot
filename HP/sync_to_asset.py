import socket

from config import ROUTER_IP, ROUTER_PORT


def notify_registration(username, password_hash):
    """Someone registered here, on the honeypot - send it to the asset so it
    becomes a real account there too (otherwise it can never be whitelisted)."""
    try:
        with socket.create_connection((ROUTER_IP, ROUTER_PORT), timeout=3) as s:
            s.sendall(f"REGISTER {username} {password_hash}".encode())
        print(f"sent the new account '{username}' to the asset")
    except OSError:
        print(f"could not reach the asset to register '{username}' for real")