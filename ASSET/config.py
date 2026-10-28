ASSET_IP = "192.168.1.127"  # this computer's own LAN IP
HP_IP = "192.168.1.145"     # the honeypot, a different computer on the same LAN
PORT = 5000                # both the asset and the honeypot listen on this port
SYNC_PORT = 9001
LISTEN_PORT = 9000  # the honeypot sends whitelist requests to this port