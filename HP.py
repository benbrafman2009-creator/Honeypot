import logging

import site_log_reg as real_app
from decoy_HP import DECOYS, HONEYPOT_FILE
from flask import request

# Point the existing app at the honeypot file instead of the real one.
real_app.ACCOUNTS_FILE = HONEYPOT_FILE
app = real_app.app

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


@app.after_request
def log_login_attempts(response):
    """Log every login attempt; raise the alarm when a decoy account is used."""
    if request.path == "/login" and request.method == "POST":
        username = request.form.get("username", "").strip()
        success = response.status_code == 302  # app redirects on successful login
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        agent = request.headers.get("User-Agent", "-")

        if username in DECOYS:
            logging.warning(
                "DECOY HIT user=%r ip=%s success=%s agent=%r", username, ip, success, agent
            )
        else:
            logging.info("login attempt user=%r ip=%s success=%s", username, ip, success)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)