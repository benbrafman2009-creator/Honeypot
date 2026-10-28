import socket
import sqlite3

from config import SYNC_PORT

DB_FILE = "honeypot.db"


def listen():
    """The asset sends "NEWACCOUNT <username> <password_hash>" here right after
    someone registers, so real_accounts (and accounts, for login) stay in sync -
    no more copying a database file over by hand."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", SYNC_PORT))
    server.listen()
    print(f"listening for new accounts from the asset on port {SYNC_PORT}")
    while True:
        conn, _ = server.accept()
        try:
            parts = conn.recv(500).decode(errors="ignore").split(" ", 2)
        except OSError:
            parts = []
        conn.close()

        if len(parts) == 3 and parts[0] == "NEWACCOUNT":
            username, password_hash = parts[1], parts[2]
            db = sqlite3.connect(DB_FILE)
            db.execute("INSERT OR REPLACE INTO real_accounts VALUES (?, ?)", (username, password_hash))
            db.execute("INSERT OR REPLACE INTO accounts VALUES (?, ?)", (username, password_hash))
            db.commit()
            db.close()
            print(f"synced real account: {username}")
        else:
            print("ignored a sync message")