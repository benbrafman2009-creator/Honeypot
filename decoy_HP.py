import os
import pickle

from werkzeug.security import generate_password_hash

REAL_FILE = "accounts.pkl"
HONEYPOT_FILE = "honeypot_accounts.pkl"

# Fake accounts that look attractive to an attacker (username: weak password).
# Nobody legitimate should ever log in with these.
#TODO: add more
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


def build_honeypot():
    # Start from the real accounts
    accounts = {}
    if os.path.exists(REAL_FILE):
        with open(REAL_FILE, "rb") as f:
            accounts = pickle.load(f)

    #then add the decoys on top
    added = []
    for username, password in DECOYS.items():
        #make sure i dont overwrite account with the decoy.
        if username not in accounts:
            accounts[username] = generate_password_hash(password)
            added.append(username)

    with open(HONEYPOT_FILE, "wb") as f:
        pickle.dump(accounts, f)
    #test print
    print(f"Honeypot written to {HONEYPOT_FILE}")
    print(f"  total accounts: {len(accounts)}")
    print(f"  decoys added:   {', '.join(added) if added else '(none)'}")


if __name__ == "__main__":
    build_honeypot()