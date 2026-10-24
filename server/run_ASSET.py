from APP import app
from config import REAL_PORT
from ARP import announce_to_router

# Start the router first, then this: it tells the router our IP.
try:
    announce_to_router()
except OSError:
    print("COULD NOT REACH THE ROUTER - start changepac.py first, then run: ARP.py")

# The real site, reachable from other computers.
print(f"real site starting on port {REAL_PORT}")
app.run(host="0.0.0.0", port=REAL_PORT)