#!/usr/bin/env python3
"""Sandtrap lure (runs INSIDE the sandbox, loopback only): fake DNS + sniffing TCP sink.

Modes
  observe : DNS answers NXDOMAIN for everything (the sample sees "no internet") but every query name is logged.
  lure    : DNS answers 127.0.0.1 for every A query; the TCP sink (ports 80, 443, 8080) accepts connections,
            logs HTTP requests (method/host/path/headers/body), TLS ClientHello SNI, or raw bytes, and replies
            with --reply-file for HTTP. Bodies are scanned for canary tokens (plain, urlencoded, base64).
Log: one JSON object per line (types: dns, http, tls, tcp). Nothing here ever talks to a real network.
"""

import argparse
import base64
import json
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
import urllib.parse

LOCK = threading.Lock()
START = time.time()
LOGFILE = "/tmp/sink.jsonl"
TOKENS: list[str] = []
REPLY = b'{"ok": true}'
MODE = "observe"


def log(record: dict) -> None:
    record["t"] = round(time.time() - START, 3)
    with LOCK, open(LOGFILE, "a") as handle:
        handle.write(json.dumps(record) + "\n")


def canaries_in(text: str) -> list[str]:
    haystacks = [text, urllib.parse.unquote_plus(text)]
    for blob in (text, text.strip()):
        try:
            haystacks.append(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("latin-1"))
        except Exception:
            pass
    found = [t for t in TOKENS if any(t in h for h in haystacks)]
    return sorted(set(found))


# ---- DNS -----------------------------------------------------------------------------------------------------
def parse_qname(packet: bytes) -> tuple[str, int, int]:
    pos, labels = 12, []
    while pos < len(packet) and packet[pos] != 0:
        length = packet[pos]
        labels.append(packet[pos + 1 : pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    qtype = struct.unpack("!H", packet[pos + 1 : pos + 3])[0] if pos + 3 <= len(packet) else 0
    return ".".join(labels), qtype, pos + 5


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if len(data) < 17:
            return
        name, qtype, end = parse_qname(data)
        question = data[12:end]
        ident = data[:2]
        answered = MODE == "lure" and qtype == 1
        if MODE == "lure":
            flags = b"\x81\x80"  # NOERROR
            count = b"\x00\x01" if qtype == 1 else b"\x00\x00"
        else:
            flags = b"\x81\x83"  # NXDOMAIN
            count = b"\x00\x00"
        reply = ident + flags + b"\x00\x01" + count + b"\x00\x00\x00\x00" + question
        if answered:
            reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
        sock.sendto(reply, self.client_address)
        if name and qtype in (1, 28, 255):
            log({"type": "dns", "name": name.lower(), "qtype": qtype, "answered": answered})


# ---- TCP sink ------------------------------------------------------------------------------------------------
def parse_sni(hello: bytes) -> str:
    try:
        pos = 43  # record(5) + handshake(4) + version(2) + random(32)
        pos += 1 + hello[pos]  # session id
        pos += 2 + struct.unpack("!H", hello[pos : pos + 2])[0]  # cipher suites
        pos += 1 + hello[pos]  # compression
        end = pos + 2 + struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            ext, length = struct.unpack("!HH", hello[pos : pos + 4])
            if ext == 0:
                return hello[pos + 9 : pos + 4 + length].decode("latin-1")
            pos += 4 + length
    except Exception:
        pass
    return ""


def original_dst(sock: socket.socket) -> str:
    try:
        raw = sock.getsockopt(socket.SOL_IP, 80, 16)  # SO_ORIGINAL_DST (set by iptables REDIRECT)
        port, addr = struct.unpack("!2xH4s8x", raw)
        return f"{socket.inet_ntoa(addr)}:{port}"
    except Exception:
        return ""


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn: socket.socket = self.request
        conn.settimeout(3.0)
        dst = original_dst(conn)
        port = conn.getsockname()[1]
        try:
            first = conn.recv(65536)
        except Exception:
            first = b""
        if not first:
            log({"type": "tcp", "port": port, "orig_dst": dst, "text": "", "note": "connect without data"})
            return
        if first[0] == 0x16 and len(first) > 5:  # TLS ClientHello: no MITM, but SNI names the destination
            log({"type": "tls", "port": port, "orig_dst": dst, "sni": parse_sni(first)})
            return
        head, _, body = first.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) >= 3 and parts[2].startswith("HTTP/"):
            headers = {}
            for line in lines[1:]:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
            want = int(headers.get("content-length", "0") or 0)
            while len(body) < min(want, 1_000_000):
                try:
                    chunk = conn.recv(65536)
                except Exception:
                    break
                if not chunk:
                    break
                body += chunk
            text = body.decode("utf-8", "replace")
            full = parts[1] + " " + json.dumps(headers) + " " + text
            log({
                "type": "http", "port": port, "orig_dst": dst, "method": parts[0], "path": parts[1],
                "host": headers.get("host", ""), "headers": headers, "body": text[:4000],
                "canaries": canaries_in(full),
            })
            try:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                    + str(len(REPLY)).encode() + b"\r\n\r\n" + REPLY
                )
            except Exception:
                pass
            return
        text = first.decode("latin-1")
        log({"type": "tcp", "port": port, "orig_dst": dst, "text": text[:600], "canaries": canaries_in(text)})


class ReuseTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReuseUdp(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    global LOGFILE, TOKENS, REPLY, MODE
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["observe", "lure"], default="observe")
    ap.add_argument("--log", default="/tmp/sink.jsonl")
    ap.add_argument("--tokens", default="")
    ap.add_argument("--reply-file", default="")
    ap.add_argument("--ports", default="80,443,8080")
    ap.add_argument("--ready", default="")
    args = ap.parse_args()
    LOGFILE, MODE = args.log, args.mode
    if args.tokens:
        TOKENS = [line.strip() for line in open(args.tokens) if line.strip()]
    if args.reply_file:
        REPLY = open(args.reply_file, "rb").read() or REPLY
    servers = [ReuseUdp(("127.0.0.1", 53), DnsHandler)]
    if MODE == "lure":
        for port in (int(p) for p in args.ports.split(",") if p):
            servers.append(ReuseTcp(("127.0.0.1", port), TcpHandler))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.ready:
        open(args.ready, "w").write("ready")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        time.sleep(0.5)


if __name__ == "__main__":
    main()
