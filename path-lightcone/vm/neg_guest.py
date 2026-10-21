"""PATHGATE-3 guest helper: real listeners on untrained services, and the live negative probes.
Extends Imperium's traffic_guest (shared read-only at /lab) from outside; same logs and markers."""

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, "/lab")
import traffic_guest as t  # noqa: E402

NEGATIVES = {
    "neg_udp_port": (4, "udp", "192.0.2.2", "198.51.100.2", 45996, 5),
    "neg_tcp_port": (4, "tcp", "192.0.2.2", "198.51.100.2", 46002, 3),
    "neg_protocol": (4, "tcp", "192.0.2.2", "198.51.100.2", 45998, 3),
    "neg_address": (4, "udp", "192.0.2.77", "198.51.100.2", 45998, 5),
    "neg_tunnel_port": (4, "udp", "10.88.0.1", "10.99.0.1", 45996, 5),
}
t.CASES.update(NEGATIVES)


def serve():
    specs = [(4, "udp", "0.0.0.0", 45996), (4, "tcp", "0.0.0.0", 46002), (4, "tcp", "0.0.0.0", 45998)]
    for family, protocol, address, port in specs:
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        connection = t.make_socket(family, kind, address, port)
        worker = threading.Thread(target=t.udp_server if protocol == "udp" else t.tcp_server,
                                  args=(connection, family), daemon=True)
        worker.start()
    (t.CONTROL / "neg-ready").write_text("ready")
    time.sleep(1200)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        t.probe(sys.argv[2])
