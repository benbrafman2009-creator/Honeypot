"""
Pickle-backed IP lists shared by the diverter and the honeypot.

whitelist.pkl - IPs that are sent to the REAL server
flagged.pkl - IPs that did something suspicious in the honeypot

CLI:
    python whitelist.py add 192.168.1.10 - add to whitelist
    python whitelist.py remove 192.168.1.10 - del from white list
    python whitelist.py list - print whitelist
    python whitelist.py flagged - shows sus login attempts
    python whitelist.py unflag 192.168.1.10
"""
import os
import pickle
import sys
import time

WHITELIST_FILE = "whitelist.pkl"
FLAGGED_FILE = "flagged.pkl"

_cache = {}


def _load(path):
    """Load a set from a pickle file, re-reading only when the file changed."""
    try:
        mtime = os.stat(path).st_mtime_ns
    except FileNotFoundError:
        return set()

    cached = _cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]

    for _ in range(10):  # the other process may be replacing the file right now
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            _cache[path] = (mtime, data)
            return data
        except (PermissionError, EOFError, pickle.UnpicklingError):
            time.sleep(0.05)
    return cached[1] if cached else set()


def _save(path, data):
    """Write atomically so a reader never sees a half-written pickle."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(data, f)
    for _ in range(10):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:  # Windows: reader has the file open for a moment
            time.sleep(0.05)
    os.replace(tmp, path)


def _add(path, ip):
    data = set(_load(path))
    data.add(ip)
    _save(path, data)


def _remove(path, ip):
    data = set(_load(path))
    data.discard(ip)
    _save(path, data)


# ---------- public API ----------
def is_whitelisted(ip):
    return ip in _load(WHITELIST_FILE)


def add_ip(ip):
    _add(WHITELIST_FILE, ip)


def remove_ip(ip):
    _remove(WHITELIST_FILE, ip)


def is_flagged(ip):
    return ip in _load(FLAGGED_FILE)


def flag_ip(ip):
    _add(FLAGGED_FILE, ip)


def unflag_ip(ip):
    _remove(FLAGGED_FILE, ip)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    arg = sys.argv[2] if len(sys.argv) > 2 else None

    if cmd == "add" and arg:
        add_ip(arg)
        print(f"whitelisted {arg}")
    elif cmd == "remove" and arg:
        remove_ip(arg)
        print(f"removed {arg}")
    elif cmd == "unflag" and arg:
        unflag_ip(arg)
        print(f"unflagged {arg}")
    elif cmd == "list":
        print("\n".join(sorted(_load(WHITELIST_FILE))) or "(whitelist is empty)")
    elif cmd == "flagged":
        print("\n".join(sorted(_load(FLAGGED_FILE))) or "(no flagged IPs)")
    else:
        print(__doc__)