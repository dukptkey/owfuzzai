#!/usr/bin/env python3
"""Tier-1 corpus synthesizer for owfuzz.

Turns a frame/IE schema into IEEE 802.11 management frames and writes them in
owfuzz's replay format (one frame per line, each byte as \\xHH) so they can be
fed via `owfuzz -T 0 -p <file>`. owfuzz rewrites addr1/2/3 at send time, so the
placeholder addresses here are fine.

The schema is the contract the (future) Spec-Reader agent will emit. A built-in
sample is used unless --schema FILE is given (JSON content; bytes encoded as hex
strings).
"""
import argparse
import json
import sys

TYPE_MGMT = 0


def fc_byte0(subtype, ftype=TYPE_MGMT):
    # 802.11 Frame Control octet 0: subtype(4) | type(2) | protocol(2).
    return ((subtype & 0x0F) << 4) | ((ftype & 0x03) << 2)


def mac_header(subtype):
    # 24-byte 802.11 MAC header: FC(2) Duration(2) Addr1(6) Addr2(6) Addr3(6) SeqControl(2).
    # Only FC octet 0 carries the subtype; the rest are placeholders — owfuzz overwrites
    # the addresses and sets the sequence number at send time. Must be exactly 24 bytes to
    # match owfuzz's `struct ieee_hdr`, or the frame body is misaligned.
    return bytes([fc_byte0(subtype)]) + bytes(23)


def ie(eid, value, length=None):
    # Information element: id(1) | length(1) | value. length may be spoofed.
    if length is None:
        length = len(value)
    return bytes([eid & 0xFF, length & 0xFF]) + value


def build(frame, ies):
    return mac_header(frame["subtype"]) + frame.get("fixed", b"") + b"".join(ies)


def to_owfuzz_hex(raw):
    return "".join("\\x%02X" % b for b in raw)


def sample_schema():
    """A few management frames the Spec-Reader will later produce from the spec."""
    return {
        "beacon": {
            "subtype": 0x08,
            "fixed": bytes(8) + (100).to_bytes(2, "little") + (0x0431).to_bytes(2, "little"),
            "ies": [
                {"id": 0, "value": b"owfuzzai"},                                    # SSID
                {"id": 1, "value": bytes([0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C])},  # rates
                {"id": 3, "value": bytes([1])},                                     # DS param (channel)
            ],
        },
        "probe_request": {
            "subtype": 0x04,
            "fixed": b"",
            "ies": [
                {"id": 0, "value": b"owfuzzai"},
                {"id": 1, "value": bytes([0x82, 0x84, 0x8B, 0x96])},
            ],
        },
        "authentication": {
            "subtype": 0x0B,
            "fixed": (0).to_bytes(2, "little") + (1).to_bytes(2, "little") + (0).to_bytes(2, "little"),
            "ies": [],
        },
        "assoc_request": {
            "subtype": 0x00,
            "fixed": (0x0431).to_bytes(2, "little") + (10).to_bytes(2, "little"),
            "ies": [
                {"id": 0, "value": b"owfuzzai"},
                {"id": 1, "value": bytes([0x82, 0x84, 0x8B, 0x96])},
                {"id": 48, "value": bytes([0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04])},   # RSNE (partial)
            ],
        },
    }


def baseline_ies(frame):
    return [ie(e["id"], e["value"]) for e in frame["ies"]]


def mutations(frame):
    """Adversarial-but-parseable IE variants: (label, ie_list)."""
    base = frame["ies"]
    out = []
    if base:
        first = base[0]
        rest = [ie(x["id"], x["value"]) for x in base[1:]]
        # Non-empty seed so the length/size operators below never collapse to a no-op
        # when the baseline value is empty (e.g. a network-specific SSID the spec leaves blank).
        seed = first["value"] or b"\x41"
        # IE length field larger than the bytes actually present -> parser over-read.
        out.append(("len_overflow", [ie(first["id"], seed, len(seed) + 32)] + rest))
        # Oversized value: absolute over-long payload (255B, past the 32-byte SSID cap),
        # independent of the baseline length so it grows even from an empty/short value.
        big = (seed * (255 // len(seed) + 1))[:255]
        out.append(("oversized_value", [ie(first["id"], big)] + rest))
        # Duplicate first IE.
        out.append(("dup_ie", [ie(first["id"], first["value"]), ie(first["id"], first["value"])] + rest))
        # Drop the (mandatory) first IE.
        out.append(("missing_mandatory", rest))
        # Zero-length IE.
        out.append(("zero_len_ie", [ie(first["id"], b"", 0)] + rest))
    # Inject a reserved IE id.
    out.append(("reserved_ie", [ie(x["id"], x["value"]) for x in base] + [ie(2, bytes(8))]))
    return out


def generate(schema, plan=None):
    plan = plan or {}
    focus_frames = set(plan.get("focus_frames") or [])
    drop_frames = set(plan.get("drop_frames") or [])
    focus_muts = set(plan.get("focus_mutations") or [])
    frames = []
    for name, fr in schema.items():
        if focus_frames and name not in focus_frames:
            continue
        if name in drop_frames:
            continue
        frames.append(("%s/baseline" % name, build(fr, baseline_ies(fr))))
        for label, ies in mutations(fr):
            if focus_muts and label not in focus_muts:
                continue
            frames.append(("%s/%s" % (name, label), build(fr, ies)))
    return frames


def load_plan(path):
    with open(path) as f:
        return json.load(f)


def write_corpus(frames, output, write_labels=False):
    with open(output, "w") as f:
        for _, raw in frames:
            f.write(to_owfuzz_hex(raw) + "\n")
    if write_labels:
        with open(output + ".labels", "w") as f:
            f.write("# idx\tlabel\tlen\n")
            for idx, (label, raw) in enumerate(frames):
                f.write("%d\t%s\t%d\n" % (idx, label, len(raw)))


def load_schema(path):
    with open(path) as f:
        raw = json.load(f)
    # bytes are hex strings in the file -> decode to bytes.
    for fr in raw.values():
        if isinstance(fr.get("fixed"), str):
            fr["fixed"] = bytes.fromhex(fr["fixed"])
        for e in fr.get("ies", []):
            if isinstance(e.get("value"), str):
                e["value"] = bytes.fromhex(e["value"])
    return raw


def main():
    ap = argparse.ArgumentParser(description="Tier-1 owfuzz corpus synthesizer")
    ap.add_argument("-o", "--output", default="agent_corpus.txt")
    ap.add_argument("--schema", help="schema file (JSON content); default = built-in sample")
    ap.add_argument("--plan", help="fuzz_plan file from triage.py to focus generation (optional)")
    ap.add_argument("--labels", action="store_true", help="also write <output>.labels mapping line -> frame")
    args = ap.parse_args()

    schema = load_schema(args.schema) if args.schema else sample_schema()
    plan = load_plan(args.plan) if args.plan else None
    frames = generate(schema, plan)
    write_corpus(frames, args.output, write_labels=args.labels)
    print("wrote %d frames -> %s" % (len(frames), args.output), file=sys.stderr)


if __name__ == "__main__":
    main()
