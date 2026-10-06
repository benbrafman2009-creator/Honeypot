import os
import pickle

from flask import Flask, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "12345"  # needed for sessions

ACCOUNTS_FILE = "accounts.pkl"


# ---------- pickle storage ----------
def load_accounts():
    """Return the {username: password_hash} dict from the pickle file."""
    if not os.path.exists(ACCOUNTS_FILE):
        return {}
    with open(ACCOUNTS_FILE, "rb") as f:
        return pickle.load(f)


def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "wb") as f:
        pickle.dump(accounts, f)


# ---------- HTML templates ----------
BASE = """
<!doctype html>
<title>{{ title }}</title>
<style>
  body { font-family: sans-serif; max-width: 360px; margin: 80px auto; }
  input, button { width: 100%; padding: 10px; margin: 6px 0; box-sizing: border-box; }
  .error { color: #c00; }
  .ok { color: #090; }
</style>
<h2>{{ title }}</h2>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
{% if message %}<p class="ok">{{ message }}</p>{% endif %}
{{ body|safe }}
"""

LOGIN_BODY = """
<form method="post">
  <input name="username" placeholder="Username" required>
  <input name="password" type="password" placeholder="Password" required>
  <button type="submit">Log in</button>
</form>
<p>No account? <a href="/register">Register</a></p>
"""

REGISTER_BODY = """
<form method="post">
  <input name="username" placeholder="Username" required>
  <input name="password" type="password" placeholder="Password" required>
  <input name="confirm" type="password" placeholder="Confirm password" required>
  <button type="submit">Create account</button>
</form>
<p>Already registered? <a href="/login">Log in</a></p>
"""

HOME_BODY = """
<p>Welcome, <b>{{ user }}</b>!</p>
<p><a href="/logout">Log out</a></p>
"""


def page(title, body, **ctx):
    return render_template_string(BASE, title=title, body=render_template_string(body, **ctx), **ctx)


# ---------- routes ----------
@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return page("Home", HOME_BODY, user=session["user"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm = request.form["confirm"]

        accounts = load_accounts()
        if not username:
            return page("Register", REGISTER_BODY, error="Username can't be empty.")
        if username in accounts:
            return page("Register", REGISTER_BODY, error="That username is taken.")
        if password != confirm:
            return page("Register", REGISTER_BODY, error="Passwords don't match.")

        accounts[username] = generate_password_hash(password)  # never store plain text
        save_accounts(accounts)
        return redirect(url_for("login", registered=1))

    return page("Register", REGISTER_BODY)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = "Account created! You can log in now." if request.args.get("registered") else None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        accounts = load_accounts()
        if username in accounts and check_password_hash(accounts[username], password):
            session["user"] = username
            return redirect(url_for("home"))
        return page("Login", LOGIN_BODY, error="Wrong username or password.")

    return page("Login", LOGIN_BODY, message=message)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)