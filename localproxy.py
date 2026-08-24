#!/usr/bin/env python3
"""
Local CONNECT-forwarding proxy shim.

Chromium (headless) fails to tunnel https through the upstream MITM proxy
(ERR_CONNECTION_RESET) even though raw sockets / curl succeed. This shim listens
on 127.0.0.1:<PORT>, and for each CONNECT it opens its own socket to the upstream
proxy, issues the same CONNECT (which is known to work), then pipes bytes both
ways. Plain-HTTP requests get a stub 200 so connectivity checks don't stall.
"""
import socket, threading, sys, re

LISTEN = ("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8899)
UP_HOST, UP_PORT = "127.0.0.1", 42785


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


def handle(client):
    try:
        client.settimeout(20)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                client.close(); return
            buf += chunk
            if len(buf) > 65536:
                client.close(); return
        line = buf.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        m = re.match(r"CONNECT\s+(\S+)\s+HTTP", line, re.I)
        if not m:
            # plain HTTP request (connectivity check) -> stub empty 200
            try:
                client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            client.close(); return
        target = m.group(1)
        up = socket.create_connection((UP_HOST, UP_PORT), timeout=20)
        up.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        # read upstream response headers
        resp = b""
        up.settimeout(20)
        while b"\r\n\r\n" not in resp:
            c = up.recv(4096)
            if not c:
                break
            resp += c
        if b" 200 " not in resp.split(b"\r\n", 1)[0]:
            try:
                client.sendall(resp or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
            client.close(); up.close(); return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        client.settimeout(None); up.settimeout(None)
        t1 = threading.Thread(target=pipe, args=(client, up), daemon=True)
        t2 = threading.Thread(target=pipe, args=(up, client), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        client.close(); up.close()
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print(f"localproxy listening on {LISTEN} -> upstream {UP_HOST}:{UP_PORT}", flush=True)
    while True:
        cli, _ = srv.accept()
        threading.Thread(target=handle, args=(cli,), daemon=True).start()


if __name__ == "__main__":
    main()
