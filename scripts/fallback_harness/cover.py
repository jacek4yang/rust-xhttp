#!/usr/bin/env python3
"""Fake cover target with controllable behaviors, for fallback-isolation testing.
Usage: cover.py <port> <mode>   mode: blackhole|echo|refuse|fin|slow|count
Prints, on SIGTERM/interrupt, the total accepted-connection count to stderr."""
import socket, sys, threading, time, signal

PORT = int(sys.argv[1]); MODE = sys.argv[2] if len(sys.argv) > 2 else "blackhole"
accepted = 0
lock = threading.Lock()

def handle(c):
    global accepted
    with lock: accepted += 1
    try:
        if MODE == "blackhole":
            # Accept and never respond, never close: hold the connection open.
            while True:
                # Drain anything sent so the socket stays "alive" but produce nothing.
                try:
                    c.settimeout(60)
                    if not c.recv(65536): break
                except socket.timeout:
                    pass
                except OSError:
                    break
        elif MODE == "echo":
            while True:
                b = c.recv(65536)
                if not b: break
                c.sendall(b)
        elif MODE == "fin":
            c.close()
        elif MODE == "slow":
            time.sleep(5); c.sendall(b"x"); c.close()
    except OSError:
        pass
    finally:
        try: c.close()
        except OSError: pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if MODE == "refuse":
        # Bind but do not listen → connections get RST (connection refused).
        s.bind(("127.0.0.1", PORT)); print(f"cover refuse on {PORT}", flush=True)
        signal.pause(); return
    s.bind(("127.0.0.1", PORT)); s.listen(4096)
    print(f"cover {MODE} on {PORT}", flush=True)
    def report(*_):
        sys.stderr.write(f"COVER_ACCEPTED={accepted}\n"); sys.stderr.flush(); sys.exit(0)
    signal.signal(signal.SIGTERM, report); signal.signal(signal.SIGINT, report)
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
