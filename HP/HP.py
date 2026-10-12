import logging
import pickle
import socket

import site_log_reg as login_app
from flask import request, session
from decoy_HP import DECOYS, HONEYPOT_FILE, REAL_FILE
from werkzeug.security import check_password_hash

ROUTER_IP = "192.168.1.1"  # the router, which keeps the whitelist
ROUTER_PORT = 9000

# Use the honeypot accounts instead of the real ones.
login_app.ACCOUNTS_FILE = HONEYPOT_FILE
app = login_app.app
#cretaed with: python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = "e69de28fac881102c5043df9aff15b8ffa583e1a7dbe5353266afdb7ce8e8068"

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

flagged_ips = set()  # IPs that used a decoy account (forgotten when the HP restarts)


def is_real_user(username, password):
    """Check against the real accounts (anyone can register here, those must not count)."""
    with open(REAL_FILE, "rb") as f:
        real_accounts = pickle.load(f)
    return username in real_accounts and check_password_hash(real_accounts[username], password)


def tell_router_to_whitelist(ip):
    try:
        with socket.create_connection((ROUTER_IP, ROUTER_PORT), timeout=3) as s:
            s.sendall(ip.encode())
    except OSError:
        logging.error("could not reach the router to whitelist %s", ip)


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
        tell_router_to_whitelist(ip)
        logging.info("WHITELISTED user=%r ip=%s", username, ip)
        session.pop("user", None)
        response.headers["Connection"] = "close"  # next request = new connection = goes to the asset

    else:
        logging.info("login attempt user=%r ip=%s ok=%s", username, ip, login_ok)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)