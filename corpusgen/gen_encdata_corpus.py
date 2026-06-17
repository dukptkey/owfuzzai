#!/usr/bin/env python3
"""Bootstrap corpus of plaintext post-association DATA frames (tagged @send=encdata).

owfuzz CCMP-encrypts each (with the session TK from the completed 4-way) before
sending, so the AP decrypts and parses it -> the encrypted-data-path parser surface.
Non-QoS data frames only (FC 0x08, 24-byte header) to match ccmp_protect. owfuzz
rewrites addr1/2/3 (ToDS) at send time. Run: python3 gen_encdata_corpus.py -o encdata_corpus.txt
"""
import argparse

DATA_FC0 = 0x08        # data frame, subtype 0
DATA_FC1 = 0x01        # ToDS (STA -> AP)
LLC = bytes.fromhex("aaaa03000000")   # SNAP; ethertype follows


def machdr():
    return bytes([DATA_FC0, DATA_FC1]) + bytes(22)   # 24-byte header placeholder


def frame(ethertype, payload):
    return machdr() + LLC + ethertype + payload


def to_hex(raw):
    return "".join("\\x%02X" % b for b in raw)


def variants():
    pat = bytes(range(1, 65)) * 6
    ip = bytes.fromhex("45000028") + pat[:36]          # IPv4-ish header + body
    out = [
        ("ip_min",        frame(b"\x08\x00", ip[:20])),            # short IP
        ("ip_oversize",   frame(b"\x08\x00", pat[:250])),          # over-long
        ("ip_badihl",     frame(b"\x08\x00", b"\x4f" + ip[1:40])), # IHL=15 (60B) but short
        ("ip_totlen_big", frame(b"\x08\x00", b"\x45\x00\xff\xff" + pat[:30])),  # total len huge
        ("arp",           frame(b"\x08\x06", bytes.fromhex("0001080006040001") + pat[:20])),
        ("ethertype_0",   frame(b"\x00\x00", pat[:20])),           # unknown ethertype
        ("llc_trunc",     machdr() + b"\xaa\xaa"),                 # truncated LLC/SNAP
    ]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="encdata_corpus.txt")
    args = ap.parse_args()
    frames = variants()
    with open(args.output, "w") as f:
        for _, raw in frames:
            f.write("# @send=encdata\n")
            f.write(to_hex(raw) + "\n")
    print("wrote %d encdata frames -> %s" % (len(frames), args.output))


if __name__ == "__main__":
    main()
