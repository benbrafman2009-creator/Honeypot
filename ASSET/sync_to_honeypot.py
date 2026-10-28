import socket

from config import HP_IP, SYNC_PORT


def notify_new_account(username, password_hash):
    """Tell the honeypot about a newly registered account, right when it happens -
    no more copying accounts.db over by hand."""
    try:
        with socket.create_connection((HP_IP, SYNC_PORT), timeout=3) as s:
            s.sendall(f"NEWACCOUNT {username} {password_hash}".encode())
        print(f"sent the new account '{username}' to the honeypot")
    except OSError:
        print(f"could not reach the honeypot to sync '{username}' - it won't be able to whitelist this user yet")