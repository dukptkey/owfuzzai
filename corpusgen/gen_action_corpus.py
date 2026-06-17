#!/usr/bin/env python3
"""Bootstrap fuzz corpus for 802.11 ACTION frames (mgmt subtype 13).

For the first post-association experiment: an associated STA injects malformed
action frames to reach the AP's action-frame parser. Hand-built (a handful of
categories x malformations); fold into the spec-driven synthesizer if it pays off.

owfuzz replay format (one frame per line, \\xHH bytes). owfuzz rewrites addr1/2/3
at send time, so the 24-byte header is a placeholder except the FC subtype.
Run: python3 gen_action_corpus.py -o action_corpus.txt --labels
"""
import argparse

ACTION_FC0 = 0xD0  # FrameControl octet0: subtype 13 (Action) | type 0 (mgmt)

# category id -> name. Mix of robust/parser-heavy categories + reserved/unknown.
CATS = {0x04: "public", 0x05: "radio_meas", 0x07: "ht", 0x0a: "wnm",
        0x15: "vht", 0x7e: "vendor", 0xff: "reserved"}


def machdr():
    return bytes([ACTION_FC0]) + bytes(23)   # FC(2) Dur(2) A1 A2 A3 Seq -> 24B placeholder


def frame(body):
    return machdr() + body


def to_hex(raw):
    return "".join("\\x%02X" % b for b in raw)


def variants(cat):
    """(label, body) malformations for one action category."""
    pat = bytes(range(1, 33)) * 9          # deterministic filler
    out = [
        ("base",      bytes([cat, 0x00]) + pat[:6]),                 # category + action 0 + small body
        ("act_max",   bytes([cat, 0xFF]) + pat[:6]),                 # unknown/reserved action code
        ("oversize",  bytes([cat, 0x01]) + pat[:250]),               # very long body -> over-read
        ("trunc",     bytes([cat])),                                 # category only (no action code)
        ("len_ie",    bytes([cat, 0x00]) + bytes([0xdd, 0xff]) + pat[:8]),  # vendor IE claims len 0xff
        ("zero",      bytes([cat, 0x00]) + bytes(60)),               # all-zero body
    ]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="action_corpus.txt")
    ap.add_argument("--labels", action="store_true")
    args = ap.parse_args()
    frames = []
    for cat, name in CATS.items():
        for label, body in variants(cat):
            frames.append(("%s/%s" % (name, label), frame(body)))
    with open(args.output, "w") as f:
        for _, raw in frames:
            f.write(to_hex(raw) + "\n")
    if args.labels:
        with open(args.output + ".labels", "w") as f:
            f.write("# idx\tlabel\tlen\n")
            for i, (lab, raw) in enumerate(frames):
                f.write("%d\t%s\t%d\n" % (i, lab, len(raw)))
    print("wrote %d action frames -> %s" % (len(frames), args.output))


if __name__ == "__main__":
    main()
