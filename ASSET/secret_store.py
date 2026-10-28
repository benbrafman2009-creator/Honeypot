import os
import secrets


def get_secret(filename):
    """Return the secret stored in a file, so it never appears in the code.
    If the file doesn't exist yet, a new random secret is created in it."""
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write(secrets.token_hex(32))
        print(f"created {filename} with a new random secret")
    with open(filename) as f:
        return f.read().strip()