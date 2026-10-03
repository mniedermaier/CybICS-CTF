"""
Check that one abusive participant cannot freeze the server.

Three attacks from a single address, each while measuring how fast the
server still answers honest requests:

  slow     many connections trickling request bodies into the device API
           (slowloris), while honest heartbeats are POSTed from the same address
  idle     many connections that send half a header and wait
  join     many devices joining the attacker's own team in parallel loops,
           which costs the server a password hash each (needs --join-code)

With --join-code, every measurement includes an honest heartbeat (a POST)
from the attacker's own address, the shared-NAT case. Used by CI against
the composed stack; run it yourself with
    python3 tools/slowloris_check.py localhost 8000 [--join-code CODE]
"""
import argparse
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

MAX_LATENCY = 2.0   # seconds an honest request may take while under attack


def post(base, path, body, token=None, timeout=10):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",  # noqa: S310
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.status, json.loads(resp.read() or b"{}")


def measure(base, token=None, rounds=5):
    """Worst latency of /healthz (and a heartbeat, given a token) over a few rounds."""
    worst = 0.0
    for _ in range(rounds):
        start = time.monotonic()
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=10) as resp:  # noqa: S310
                assert resp.status == 200
            if token:
                post(base, "/api/v1/heartbeat", {}, token)
        except (OSError, AssertionError) as exc:
            sys.exit(f"an honest request failed under attack: {exc}")
        worst = max(worst, time.monotonic() - start)
        time.sleep(1)
    return worst


def slow_uploads(host, port, stop, count):
    def one():
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"POST /api/v1/solves HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                      b"Content-Length: 60000\r\n\r\n")
            while not stop.is_set():
                s.sendall(b"{")
                time.sleep(1)
        except OSError:
            pass   # dropped by the proxy: exactly what should happen
    for _ in range(count):
        threading.Thread(target=one, daemon=True).start()


def idle_headers(host, port, stop, count):
    def opener():
        held = []
        while not stop.is_set() and len(held) < count:
            try:
                s = socket.create_connection((host, port), timeout=5)
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")   # never finished
                held.append(s)
            except OSError:
                time.sleep(0.05)
        stop.wait()
        for s in held:
            s.close()
    threading.Thread(target=opener, daemon=True).start()


def enrol_device(base, join_code, hostname):
    """A device enrolled with the event's join code; returns its token."""
    _, resp = post(base, "/api/v1/enroll", {"code": join_code, "device": {"kind": "virtual", "hostname": hostname}},
                   timeout=30)
    return resp["token"]


def enroll_flood(base, stop, join_code, loops):
    """Devices joining a team over and over: every join hashes the team password."""
    def one(i):
        try:
            token = enrol_device(base, join_code, f"flood{i}")
        except (OSError, urllib.error.HTTPError):
            return
        body = {"join_code": join_code, "team_name": "Flood Team", "team_password": "flood-pass-1"}
        while not stop.is_set():
            try:
                post(base, "/api/v1/ctf/join", body, token, timeout=30)
            except (OSError, urllib.error.HTTPError):
                pass
    for i in range(loops):
        threading.Thread(target=one, args=(i,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--join-code", help="a running event's join code, enables the join phase")
    args = parser.parse_args()
    base = f"http://{args.host}:{args.port}"

    token = None
    if args.join_code:
        token = enrol_device(base, args.join_code, "honest")
        post(base, "/api/v1/ctf/join", {"join_code": args.join_code, "team_name": "Honest Team",
                                        "team_password": "honest-pass-1"}, token)

    phases = [("slow uploads x1000", lambda stop: slow_uploads(args.host, args.port, stop, 1000)),
              ("idle headers x3000", lambda stop: idle_headers(args.host, args.port, stop, 3000))]
    if args.join_code:
        phases.append(("join flood x64", lambda stop: enroll_flood(base, stop, args.join_code, 64)))

    failed = False
    for name, attack in phases:
        stop = threading.Event()
        attack(stop)
        time.sleep(4)
        worst = measure(base, token)
        stop.set()
        verdict = "ok" if worst <= MAX_LATENCY else "TOO SLOW"
        print(f"{name:20} honest worst latency {worst:.2f} s  {verdict}")
        failed |= worst > MAX_LATENCY
        time.sleep(6)   # let the attack's connections drain before the next phase
    if failed:
        sys.exit("one participant can starve the server")


if __name__ == "__main__":
    main()
