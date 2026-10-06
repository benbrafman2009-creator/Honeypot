"""
Clients always connect to REAL_PORT. For each NEW connection we check the IP:
  - whitelisted - packets pass through untouched (real server)
  - not whitelisted - dst port rewritten REAL_PORT -> HP_PORT
"""
import time

import whitelist

REAL_PORT = 5000
HP_PORT = 8080
IDLE_TIMEOUT = 300  # seconds before an idle connection is forgotten

FILTER = f"tcp and (tcp.DstPort == {REAL_PORT} or tcp.SrcPort == {HP_PORT})"

connections = {}


def handle(packet, now=None):
    #Rewrite the packet in place if it belongs to a connection sent to the honeypot.
    now = time.monotonic() if now is None else now

    if packet.dst_port == REAL_PORT:  # client -> server
        key = (packet.src_addr, packet.src_port)
        entry = connections.get(key)
        is_syn = packet.tcp.syn and not packet.tcp.ack

        if entry is None or is_syn:  # new connection: decide where it goes
            target = "real" if whitelist.is_whitelisted(packet.src_addr) else "hp"
            print(f"[{time.strftime('%H:%M:%S')}] {packet.src_addr}:{packet.src_port} -> {target.upper()}")
        else:
            target = entry[0]

        connections[key] = (target, now)
        if target == "hp":
            packet.dst_port = HP_PORT

    elif packet.src_port == HP_PORT:  # honeypot -> client
        entry = connections.get((packet.dst_addr, packet.dst_port))
        if entry and entry[0] == "hp":  # only our diverted connections, not direct hits on HP_PORT
            packet.src_port = REAL_PORT
            connections[(packet.dst_addr, packet.dst_port)] = ("hp", now)

    return packet


def sweep(now=None):
    now = time.monotonic() if now is None else now
    for key in [k for k, (_, seen) in connections.items() if now - seen > IDLE_TIMEOUT]:
        del connections[key]


def main():
    import pydivert  # Windows only, needs admin rights

    print(f"Diverting tcp/{REAL_PORT}: whitelisted -> real server, others -> honeypot on {HP_PORT}")
    count = 0
    with pydivert.Divert(FILTER) as diverter:
        for packet in diverter:
            handle(packet)
            diverter.send(packet)  # checksums are recalculated automatically
            count += 1
            if count % 5000 == 0:
                sweep()


if __name__ == "__main__":
    main()