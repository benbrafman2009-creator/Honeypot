import sqlite3

from werkzeug.security import generate_password_hash

DB_FILE = "honeypot.db"

# Fake accounts that attract attackers (username: weak password).
DECOYS = {
    "admin": "admin123",
    "root": "toor",
    "administrator": "Password1",
    "backup": "backup2024",
    "test": "test",
    "support": "Welcome1",
    "dbadmin": "qwerty123",
    "ben_admin": "letmein",
}

if __name__ == "__main__":
    db = sqlite3.connect(DB_FILE)

    # real_accounts: filled live by sync_listener.py whenever the asset registers someone
    db.execute("CREATE TABLE IF NOT EXISTS real_accounts (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")

    # decoy_accounts: logging in with one of these flags the client's IP
    db.execute("CREATE TABLE IF NOT EXISTS decoy_accounts (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")

    # "accounts" is the table app.py's login/register actually checks against -
    # every decoy also goes in here, so logging in with one works like any other account.
    db.execute("CREATE TABLE IF NOT EXISTS accounts (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")

    for username, password in DECOYS.items():
        password_hash = generate_password_hash(password)
        db.execute("INSERT OR IGNORE INTO decoy_accounts VALUES (?, ?)", (username, password_hash))
        db.execute("INSERT OR IGNORE INTO accounts VALUES (?, ?)", (username, password_hash))

    db.commit()
    counts = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("accounts", "real_accounts", "decoy_accounts")}
    db.close()
    print(f"{DB_FILE} ready: {counts}")