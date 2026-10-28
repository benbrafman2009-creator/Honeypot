import logging
import sqlite3

import app as login_app  # the same app.py as the real site (login/register untouched)
from config import PORT
from flask import request, session
from decoy_HP import DECOYS, HONEYPOT_DB
from ARP import whitelist_on_router
from secret_store import get_secret
from werkzeug.security import check_password_hash

# Use the honeypot database instead of the real one.
login_app.DB_FILE = HONEYPOT_DB
app = login_app.app

# Different key than the asset, so a honeypot session is never valid there.
app.secret_key = get_secret("honeypot_secret.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("honeypot.log"), logging.StreamHandler()],  # file + screen
)

flagged_ips = set()  # IPs that used a decoy account (forgotten when the HP restarts)


def is_real_user(username, password):
    """real_usernames only gets filled by make_honeypot.py, never by /register,
    so an account created on the honeypot itself can never count as real."""
    db = sqlite3.connect(HONEYPOT_DB)
    is_real = db.execute("SELECT 1 FROM real_usernames WHERE username = ?", (username,)).fetchone()
    row = db.execute("SELECT password_hash FROM accounts WHERE username = ?", (username,)).fetchone()
    db.close()
    return is_real is not None and row is not None and check_password_hash(row[0], password)


@app.after_request
def watch_logins(response):
    if request.path != "/login" or request.method != "POST":
        return response

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = request.remote_addr

    if username in DECOYS:
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
    print(f"honeypot starting on port {PORT}")
    app.run(host="0.0.0.0", port=PORT)