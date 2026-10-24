import shutil
import sqlite3

from werkzeug.security import generate_password_hash

REAL_DB = "accounts.db"
HONEYPOT_DB = "honeypot.db"

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
    # make sure the real database exists, then copy it
    db = sqlite3.connect(REAL_DB)
    db.execute("CREATE TABLE IF NOT EXISTS accounts (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
    db.commit()
    db.close()
    shutil.copyfile(REAL_DB, HONEYPOT_DB)

    # add the decoys on top (a decoy never replaces a real account)
    db = sqlite3.connect(HONEYPOT_DB)
    for username, password in DECOYS.items():
        db.execute("INSERT OR IGNORE INTO accounts VALUES (?, ?)", (username, generate_password_hash(password)))
    db.commit()
    count = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    db.close()

    print(f"{HONEYPOT_DB} written with {count} accounts")