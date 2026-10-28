import logging
import sqlite3
import threading

import app as login_app  # the same app.py as the real site (login/register untouched)
import sync_listener
from config import PORT
from flask import request, session
from ARP import whitelist_on_router
from secret_store import get_secret
from werkzeug.security import check_password_hash

DB_FILE = "honeypot.db"

# Use the honeypot database instead of the real one.
login_app.DB_FILE = DB_FILE
app = login_app.app

# Different key than the asset, so a honeypot session is never valid there.
app.secret_key = get_secret("honeypot_secret.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("honeypot.log"), logging.StreamHandler()],  # file + screen
)

flagged_ips = set()  # IPs that used a decoy account (forgotten when the HP restarts)


def is_decoy(username):
    db = sqlite3.connect(DB_FILE)
    row = db.execute("SELECT 1 FROM decoy_accounts WHERE username = ?", (username,)).fetchone()
    db.close()
    return row is not None


def is_real_user(username, password):
    """real_accounts only gets filled by the asset's sync messages, never by /register,
    so an account created on the honeypot itself can never count as real."""
    db = sqlite3.connect(DB_FILE)
    row = db.execute("SELECT password_hash FROM real_accounts WHERE username = ?", (username,)).fetchone()
    db.close()
    return row is not None and check_password_hash(row[0], password)


@app.after_request
def watch_logins(response):
    if request.path != "/login" or request.method != "POST":
        return response

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = request.remote_addr

    if is_decoy(username):
        flagged_ips.add(ip)
        logging.warning("DECOY HIT user=%r ip=%s", username, ip)

    elif ip not in flagged_ips and is_real_user(username, password):
        try:
            whitelist_on_router(ip)
            logging.info("WHITELISTED user=%r ip=%s", username, ip)
        except OSError:
            logging.error("could not reach the router to whitelist %s", ip)
        session.pop("user", None)
        response.headers["Connection"] = "close"  # next request = new connection = goes to the asset

    else:
        logging.info("login attempt user=%r ip=%s", username, ip)

    return response


if __name__ == "__main__":
    threading.Thread(target=sync_listener.listen, daemon=True).start()
    print(f"honeypot starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT)