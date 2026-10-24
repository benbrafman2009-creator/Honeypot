import os
import secrets


def get_secret(filename, create=False):
    """Return the secret stored in a file, so it never appears in the code.
    create=True : make a new random secret if the file doesn't exist yet.
    create=False: the secret comes from another computer, so stop if it's missing."""
    if not os.path.exists(filename):
        if not create:
            raise SystemExit(f"{filename} not found (router.py creates it - copy it from the router computer)")
        with open(filename, "w") as f:
            f.write(secrets.token_hex(32))
        print(f"created {filename} with a new random secret")
    with open(filename) as f:
        return f.read().strip()