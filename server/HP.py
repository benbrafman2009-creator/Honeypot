import logging
import sqlite3

import APP as login_app  # the same app.py as the real site (login/register untouched)
from config import HP_PORT
from flask import request, session
from make_HP import DECOYS, HONEYPOT_DB, REAL_DB
from ARP import whitelist_on_router
from werkzeug.security import check_password_hash

# Use the honeypot database instead of the real one.
login_app.DB_FILE = HONEYPOT_DB
app = login_app.app

app.secret_key = "sh26sajmv0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("honeypot.log"), logging.StreamHandler()],  # file + screen
)

flagged_ips = set()  # IPs that used a decoy account (forgotten when the HP restarts)


def is_real_user(username, password):
    """Check against the REAL database (anyone can register in the honeypot, those must not count)."""
    db = sqlite3.connect(REAL_DB)
    try:
        row = db.execute("SELECT password_hash FROM accounts WHERE username = ?", (username,)).fetchone()
    except sqlite3.OperationalError:  # the real database has no accounts table yet
        row = None
    db.close()
    return row is not None and check_password_hash(row[0], password)


@app.after_request
def watch_logins(response):
    if request.path != "/login" or request.method != "POST":
        return response

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    login_ok = response.status_code == 302  # the app redirects after a successful login
    ip = request.remote_addr

    if username in DECOYS:
        flagged_ips.add(ip)
        logging.warning("DECOY HIT user=%r ip=%s", username, ip)

    elif login_ok and ip not in flagged_ips and is_real_user(username, password):
        try:
            whitelist_on_router(ip)
            logging.info("WHITELISTED user=%r ip=%s", username, ip)
        except OSError:
            logging.error("could not reach the router to whitelist %s", ip)
        session.pop("user", None)
        response.headers["Connection"] = "close"  # next request = new connection = goes to the real site

    else:
        logging.info("login attempt user=%r ip=%s ok=%s", username, ip, login_ok)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HP_PORT)