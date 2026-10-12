import pickle

from werkzeug.security import generate_password_hash

REAL_FILE = "reg_users/accounts.pkl"  # a copy of the asset's accounts.pkl
HONEYPOT_FILE = "reg_users/honeypot_accounts.pkl"

# Fake accounts that attract attackers (username: weak password).
#TODO: add more/add a simple API request to ai to check
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
    #Start with the real accounts...
    with open(REAL_FILE, "rb") as f:
        accounts = pickle.load(f)

    #Adds the decoys on top
    for username, password in DECOYS.items():
        if username not in accounts:
            accounts[username] = generate_password_hash(password)

    with open(HONEYPOT_FILE, "wb") as f:
        pickle.dump(accounts, f)

    print(f"{HONEYPOT_FILE} written with {len(accounts)} accounts")