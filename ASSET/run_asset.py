from app import app
from config import PORT

# The real site. Clients connect to ASSET_IP:PORT; router.py (run separately,
# as Administrator) decides whether a packet reaches this app or the honeypot.
print(f"real site starting on port {PORT}")
app.run(host="0.0.0.0", port=PORT)