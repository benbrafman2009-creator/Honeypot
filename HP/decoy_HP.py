import shutil
import sqlite3

from werkzeug.security import generate_password_hash

REAL_DB = "real_accounts.db"   # a copy of the asset's accounts.db - bring this over by hand
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
    real_db = sqlite3.connect(REAL_DB)
    real_usernames = [row[0] for row in real_db.execute("SELECT username FROM accounts")]
    real_db.close()

    shutil.copyfile(REAL_DB, HONEYPOT_DB)
    db = sqlite3.connect(HONEYPOT_DB)

    # remember which usernames are genuinely real, in a table nobody can register into
    # (so an account someone creates ON the honeypot can never pass as a real one)
    db.execute("CREATE TABLE IF NOT EXISTS real_usernames (username TEXT PRIMARY KEY)")
    db.executemany("INSERT OR IGNORE INTO real_usernames VALUES (?)", [(u,) for u in real_usernames])

    # add the decoys on top (a decoy never replaces a real account)
    for username, password in DECOYS.items():
        db.execute("INSERT OR IGNORE INTO accounts VALUES (?, ?)", (username, generate_password_hash(password)))

    db.commit()
    count = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    db.close()

    print(f"{HONEYPOT_DB} written with {count} accounts ({len(real_usernames)} of them real)")