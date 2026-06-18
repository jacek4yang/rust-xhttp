#!/usr/bin/env python3
"""Extract the server->client TLS record-length sequence from a capture.

This is a generic local pcap helper. rust-xhttp does not currently wire it into
an automated differential test.

No third-party dependencies — parses a classic `tcpdump`/libpcap file directly
(link types EN10MB=1, Linux "cooked" SLL=113 / SLLv2=276, and raw IPv4/IPv6),
reassembles the server->client TCP byte stream by sequence number, and walks the
TLS record layer (5-byte headers) printing one `type length` line per record.

Usage:
    tls_record_lens.py <capture.pcap> --server-port 443 [--server-ip 10.0.0.2]
    tls_record_lens.py <capture.pcap> --server-port 443 --first-app-only

`--first-app-only` prints just the length of the first application_data (0x17)
record after the ServerHello — the dominant DPI signal and the one the
"conservative coalesce" strategy matches exactly.
"""

import argparse
import struct
import sys

TLS_TYPES = {20: "ccs", 21: "alert", 22: "handshake", 23: "appdata"}


def read_pcap_packets(path):
    """Yield raw link-layer frames from a classic pcap file (any endianness)."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = hdr[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        else:
            sys.exit(f"not a classic pcap file (magic {magic!r}); "
                     f"convert pcapng with `editcap -F pcap`")
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            _ts, _us, caplen, _origlen = struct.unpack(endian + "IIII", ph)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            yield linktype, data


def parse_l3(linktype, frame):
    """Return the IP payload (proto, src_ip, dst_ip, l4_bytes) or None."""
    if linktype == 1:  # EN10MB (Ethernet)
        if len(frame) < 14:
            return None
        eth_type = struct.unpack(">H", frame[12:14])[0]
        off, eth_type = 14, eth_type
        # Skip one VLAN tag if present.
        if eth_type == 0x8100 and len(frame) >= 18:
            eth_type = struct.unpack(">H", frame[16:18])[0]
            off = 18
        return parse_ip(eth_type, frame[off:])
    if linktype in (113, 276):  # Linux SLL / SLLv2 ("any" interface)
        # SLL: 2 pkttype, 2 hatype, 2 halen, 8 addr, 2 proto.  SLLv2 differs but
        # the EtherType sits near the front; handle the common SLL layout.
        if linktype == 113 and len(frame) >= 16:
            proto = struct.unpack(">H", frame[14:16])[0]
            return parse_ip(proto, frame[16:])
        if linktype == 276 and len(frame) >= 20:
            proto = struct.unpack(">H", frame[0:2])[0]
            return parse_ip(proto, frame[20:])
        return None
    if linktype == 101:  # raw IP
        if not frame:
            return None
        ver = frame[0] >> 4
        return parse_ip(0x0800 if ver == 4 else 0x86DD, frame)
    return None


def parse_ip(eth_type, pkt):
    if eth_type == 0x0800:  # IPv4
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        src = ".".join(str(b) for b in pkt[12:16])
        dst = ".".join(str(b) for b in pkt[16:20])
        return proto, src, dst, pkt[ihl:]
    if eth_type == 0x86DD:  # IPv6 (no extension-header chasing; TCP-direct)
        if len(pkt) < 40:
            return None
        proto = pkt[6]
        src = ":".join(f"{pkt[i]:02x}{pkt[i+1]:02x}" for i in range(8, 24, 2))
        dst = ":".join(f"{pkt[i]:02x}{pkt[i+1]:02x}" for i in range(24, 40, 2))
        return proto, src, dst, pkt[40:]
    return None


def reassemble(path, server_port, server_ip):
    """Reassemble the server->client byte stream of the TLS *handshake* connection.

    Filters to packets sent *by* the server (src port == server_port, and the
    given server_ip if any), groups them by full TCP 4-tuple so multiple
    connections sharing the listen port are not interleaved, reassembles each by
    sequence number, and returns the stream of the connection that begins with a
    TLS handshake record (0x16). Ties are broken by the lowest starting sequence
    number (earliest connection).
    """
    conns = {}  # (src,sport,dst,dport) -> {seq: payload}
    order = []  # connection keys in first-seen order
    for linktype, frame in read_pcap_packets(path):
        l3 = parse_l3(linktype, frame)
        if not l3:
            continue
        proto, src, dst, l4 = l3
        if proto != 6 or len(l4) < 20:  # TCP
            continue
        sport, dport = struct.unpack(">HH", l4[0:4])
        if sport != server_port:
            continue
        if server_ip and src != server_ip:
            continue
        seq = struct.unpack(">I", l4[4:8])[0]
        data_off = (l4[12] >> 4) * 4
        payload = l4[data_off:]
        if not payload:
            continue
        key = (src, sport, dst, dport)
        if key not in conns:
            conns[key] = {}
            order.append(key)
        conns[key].setdefault(seq, payload)

    def stream_of(key):
        segs = conns[key]
        out = bytearray()
        for seq in sorted(segs):
            out += segs[seq]
        return bytes(out)

    # Prefer the connection whose stream starts with a handshake record.
    handshake_conns = [k for k in order if stream_of(k)[:1] == b"\x16"]
    if handshake_conns:
        # Earliest by lowest starting sequence number.
        best = min(handshake_conns, key=lambda k: min(conns[k]))
        return stream_of(best)
    # Fall back to the first connection seen (better than nothing).
    return stream_of(order[0]) if order else b""


def tls_records(stream):
    """Yield (content_type, total_on_wire_len) for each TLS record in `stream`."""
    i = 0
    while i + 5 <= len(stream):
        ctype = stream[i]
        if ctype not in TLS_TYPES:
            break  # not (or no longer) aligned to the TLS record layer
        length = struct.unpack(">H", stream[i + 3:i + 5])[0]
        total = 5 + length
        if i + total > len(stream):
            break
        yield ctype, total
        i += total


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("--server-port", type=int, required=True)
    ap.add_argument("--server-ip", default=None)
    ap.add_argument("--first-app-only", action="store_true")
    args = ap.parse_args()

    stream = reassemble(args.pcap, args.server_port, args.server_ip)
    records = list(tls_records(stream))
    if not records:
        sys.exit("no server->client TLS records found in capture")

    if args.first_app_only:
        for ctype, total in records:
            if ctype == 23:  # application_data
                print(total)
                return
        sys.exit("no application_data record found")

    for ctype, total in records:
        print(f"{TLS_TYPES.get(ctype, ctype)} {total}")


if __name__ == "__main__":
    main()
