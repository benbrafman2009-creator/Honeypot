import logging
import os
import pickle

import site_log_reg as real_app  # your original app.py, untouched (login/register logic reused as-is)
import whitelist
from flask import request, session
from decoy_HP import DECOYS, HONEYPOT_FILE, REAL_FILE
from werkzeug.security import check_password_hash

# Point the existing app at the honeypot file instead of the real one.
real_app.ACCOUNTS_FILE = HONEYPOT_FILE
app = real_app.app

# Different key than the real app, so a honeypot session cookie (e.g. one for a
# decoy account) is never accepted by the real server.
app.secret_key = "honeypot-only-key-change-me"

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def is_suspicious(username, password):
    """The only alarm for now: using a decoy account. Add more rules here later."""
    return username in DECOYS


def credentials_are_real(username, password):
    """Check against the REAL accounts file, not the honeypot copy.
    (Anyone can register in the honeypot, so honeypot-only accounts must never count.)"""
    if not os.path.exists(REAL_FILE):
        return False
    with open(REAL_FILE, "rb") as f:
        real = pickle.load(f)
    return username in real and check_password_hash(real[username], password)


@app.after_request
def watch_logins(response):
    if request.path != "/login" or request.method != "POST":
        return response

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    success = response.status_code == 302  # app redirects on successful login
    ip = request.remote_addr  # never use X-Forwarded-For here, the client controls it

    if is_suspicious(username, password):
        whitelist.flag_ip(ip)  # this IP can no longer be auto-whitelisted
        logging.warning("DECOY HIT user=%r ip=%s success=%s agent=%r",
                        username, ip, success, request.headers.get("User-Agent", "-"))

    elif success and not whitelist.is_flagged(ip) and credentials_are_real(username, password):
        whitelist.add_ip(ip)
        logging.info("WHITELISTED user=%r ip=%s", username, ip)
        session.pop("user", None)                # honeypot session isn't needed anymore
        response.headers["Connection"] = "close"  # force a NEW connection -> routed to the real server

    else:
        logging.info("login attempt user=%r ip=%s success=%s", username, ip, success)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)