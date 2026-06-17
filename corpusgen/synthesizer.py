#!/usr/bin/env python3
"""Tier-1 corpus synthesizer for owfuzz.

Turns a frame/IE schema into IEEE 802.11 management frames and writes them in
owfuzz's replay format (one frame per line, each byte as \\xHH) so they can be
fed via `owfuzz -T 0 -p <file>`. owfuzz rewrites addr1/2/3 at send time, so the
placeholder addresses here are fine.

Each frame is preceded by a directive comment that tags the protocol state and
frame type it belongs to, e.g. `# @state=AUTHENTICATING @type=AUTH`. The PoC
test (-T 0) ignores these comments and replays statelessly; the interactive
test (-T 1) parses them (see owfuzz/src/frames/corpus.h) and injects each frame
into the handshake at the matching point. The tags are plain comments, so the
file stays backward-compatible and the .labels/results idx mapping is unaffected
(owfuzz counts frames, not lines).

The schema is the contract the (future) Spec-Reader agent will emit. A built-in
sample is used unless --schema FILE is given (JSON content; bytes encoded as hex
strings).
"""
import argparse
import json
import sys

TYPE_MGMT = 0

# Map each schema frame family to the (wpa_state, frame_type) tag owfuzz's
# interactive corpus parser understands (state names from enum wpa_states,
# type names from corpus.c:type_from_name). The state is where owfuzz sends the
# frame during the STA-mode handshake; corpus_lookup treats it as a refinement,
# so the type tag is what guarantees the frame is used. Families absent here are
# emitted untagged (owfuzz then derives the type from the frame's FC octet).
STATE_TYPE_MAP = {
    "beacon":         ("SCANNING",       "BEACON"),
    "probe_request":  ("SCANNING",       "PROBEREQ"),
    "authentication": ("AUTHENTICATING", "AUTH"),
    "assoc_request":  ("ASSOCIATING",    "ASSOCREQ"),
    "sae_commit":     ("AUTHENTICATING", "AUTH"),
    "sae_confirm":    ("AUTHENTICATING", "AUTH"),
}

# Map a schema frame family to the flow-engine @send id used by a flow file
# (owfuzz/src/frames/flow.h). The generic engine sends frames by these ids, so a
# flow rule's `send` column references them. Used for Option B (stateful flows).
SEND_ID_MAP = {
    "sae_commit":  "sae_commit",
    "sae_confirm": "sae_confirm",
}


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


# --- Data frames (EAPOL / 4-way handshake) ----------------------------------
# A "data" frame carries an LLC/SNAP-encapsulated payload (e.g. EAPOL-Key) rather
# than 802.11 IEs. owfuzz rewrites addr1/2/3 from the frame's DS flags at send time
# (corpus_fixup_addrs), so we only set the ToDS bit; addresses stay placeholders.
TYPE_DATA = 2
LLC_SNAP_EAPOL = bytes.fromhex("aaaa03000000888e")  # SNAP, ethertype 0x888E (EAPOL)


def frame_kind(frame):
    return frame.get("kind", "mgmt")


def data_header(subtype, tods=True, qos_ctrl=None):
    # FC(2) Dur(2) Addr1(6) Addr2(6) Addr3(6) SeqCtrl(2) [QoSCtrl(2)]. FC octet0 carries
    # the data subtype (8 = QoS data -> 0x88), octet1 the DS flags (ToDS=0x01 = STA->AP).
    fc0 = fc_byte0(subtype, TYPE_DATA)
    fc1 = 0x01 if tods else 0x00
    hdr = bytes([fc0, fc1]) + bytes(22)  # 24-byte base header
    if qos_ctrl is not None:
        hdr += qos_ctrl                  # +2 -> 26-byte QoS header
    return hdr


def build(frame, ies, fixed=None):
    if fixed is None:
        fixed = frame.get("fixed", b"")
    if frame_kind(frame) == "data":
        hdr = data_header(frame["subtype"], frame.get("tods", True), frame.get("qos"))
        encap = LLC_SNAP_EAPOL if frame.get("encap") == "eapol" else b""
        return hdr + encap + fixed + b"".join(ies)
    return mac_header(frame["subtype"]) + fixed + b"".join(ies)


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


# EAPOL-Key body field offsets (within the EAPOL payload carried as the frame's `fixed`):
# ver(0) type(1) len(2-3) descriptor(4) keyinfo(5-6) keylen(7-8) replay(9-16) nonce(17-48)
# iv(49-64) rsc(65-72) keyid(73-80) MIC(81-96) keydatalen(97-98) keydata(99+).
EK_KEYINFO, EK_KEYLEN, EK_KDL, EK_KEYDATA = 5, 7, 97, 99


def _patch(b, off, repl):
    """Overwrite len(repl) bytes of b at off (in place, same total length)."""
    return b[:off] + repl + b[off + len(repl):]


def eapol_mutations(frame):
    """EAPOL-Key parser variants: (label, mutated_eapol_body). In-place field rewrites
    that keep the frame length but break a length/flag invariant -> classic over-read /
    state-confusion triggers. The baseline stays valid so the AP reaches the parser."""
    body = frame.get("fixed", b"")
    if len(body) < EK_KEYDATA:
        return []
    out = [
        # Key Data Length field claims far more than is present -> parser over-read.
        ("ek_kdl_overflow",     _patch(body, EK_KDL, b"\xff\xff")),
        # Key Data Length = 0 while key data is present -> length/content mismatch.
        ("ek_kdl_zero",         _patch(body, EK_KDL, b"\x00\x00")),
        # Key Length maxed.
        ("ek_keylen_max",       _patch(body, EK_KEYLEN, b"\xff\xff")),
        # Key Information all bits set (bogus descriptor version / type / flags).
        ("ek_keyinfo_ff",       _patch(body, EK_KEYINFO, b"\xff\xff")),
    ]
    # RSN element inside Key Data claims an oversized element length (id@KEYDATA, len@+1).
    if len(body) > EK_KEYDATA + 1:
        out.append(("ek_rsne_len_overflow", _patch(body, EK_KEYDATA + 1, b"\xff")))
    return out


# Fixed-field mutation table keyed by 802.11 management subtype.
# Each entry is a list of (label, transform) where transform(fixed_bytes) -> mutated_bytes.
# Fields are little-endian as on the wire.
_u16le = lambda v: v.to_bytes(2, "little")
FIXED_FIELD_MUTATIONS = {
    # Authentication: Algorithm(2) + TransactionSeq(2) + StatusCode(2)
    # Slices keep the tail (f[2:], f[4:], f[6:]) so these also work on longer
    # auth bodies (e.g. SAE commit/confirm) without truncating them; for a plain
    # 6-byte auth header the tail is empty, so behavior is unchanged.
    0x0B: [
        # Unknown algorithm -> driver hits unhandled branch
        ("auth_algo_unknown",    lambda f: _u16le(0xFFFF) + f[2:]),
        # Shared Key auth -> triggers challenge-text state machine
        ("auth_algo_sharedkey",  lambda f: _u16le(0x0001) + f[2:]),
        # SAE/WPA3 -> triggers SAE state machine on WPA2-only drivers
        ("auth_algo_sae",        lambda f: _u16le(0x0003) + f[2:]),
        # Out-of-order sequence (seq=3 before seq=1) -> state machine confusion
        ("auth_seq_oor",         lambda f: f[0:2] + _u16le(0x0003) + f[4:]),
        # Non-zero status in a request frame -> illegal per spec
        ("auth_status_nonzero",  lambda f: f[0:4] + _u16le(0x0001) + f[6:]),
    ],
    # Beacon: Timestamp(8) + BeaconInterval(2) + CapabilityInfo(2)
    0x08: [
        # Zero beacon interval -> divide-by-zero in drivers that compute TU timing
        ("beacon_interval_zero", lambda f: f[0:8] + _u16le(0x0000) + f[10:12]),
        # Max beacon interval (~65 s) -> STA retransmit/timeout edge case
        ("beacon_interval_max",  lambda f: f[0:8] + _u16le(0xFFFF) + f[10:12]),
        # All capability bits set including reserved -> mode-switching edge case
        ("beacon_cap_reserved",  lambda f: f[0:10] + _u16le(0xFFFF)),
    ],
    # Association Request: CapabilityInfo(2) + ListenInterval(2)
    0x00: [
        # All capability bits set including reserved
        ("assoc_cap_reserved",   lambda f: _u16le(0xFFFF) + f[2:4]),
        # Zero listen interval -> driver divides or compares against 0
        ("assoc_listen_zero",    lambda f: f[0:2] + _u16le(0x0000)),
        # Max listen interval -> extreme sleep-mode buffer sizing
        ("assoc_listen_max",     lambda f: f[0:2] + _u16le(0xFFFF)),
    ],
    # Action: Category(1) + Action(1) + category-specific body. Post-association
    # parser surface (reached as an associated STA; host-observable on this target).
    0x0D: [
        # Reserved/undefined category -> unhandled dispatch branch
        ("action_cat_reserved",  lambda f: b"\xff" + f[1:]),
        # Unknown action code within the category
        ("action_code_unknown",  lambda f: f[0:1] + b"\xff" + f[2:]),
        # Over-long body -> length/over-read in the category parser
        ("action_oversize",      lambda f: f + bytes(250)),
        # Category byte only, body truncated -> short-frame handling
        ("action_truncate",      lambda f: f[0:1]),
    ],
}


def fixed_mutations(frame):
    """Fixed-field variants: (label, mutated_fixed_bytes).
    Returns [] for frames with no fixed fields or no registered mutations."""
    f = frame.get("fixed", b"")
    variants = FIXED_FIELD_MUTATIONS.get(frame["subtype"], [])
    if not f or not variants:
        return []
    return [(label, xform(f)) for label, xform in variants]


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
        # Data/EAPOL frames: baseline + EAPOL-Key mutators. Management frames: baseline +
        # IE + fixed-field mutators. A frame with "fuzz": false emits only the (valid)
        # baseline — used for the flow's carrier frames (auth/assoc) that must be accepted
        # so the handshake advances to the fuzz target.
        if frame_kind(fr) == "data":
            frames.append(("%s/baseline" % name, build(fr, [])))
            if fr.get("fuzz", True):
                for label, body in eapol_mutations(fr):
                    if focus_muts and label not in focus_muts:
                        continue
                    frames.append(("%s/%s" % (name, label), build(fr, [], fixed=body)))
            continue
        frames.append(("%s/baseline" % name, build(fr, baseline_ies(fr))))
        if not fr.get("fuzz", True):
            continue
        for label, ies in mutations(fr):
            if focus_muts and label not in focus_muts:
                continue
            frames.append(("%s/%s" % (name, label), build(fr, ies)))
        # Fixed-field mutations use baseline IEs; always included for in-scope frames.
        for label, fixed in fixed_mutations(fr):
            frames.append(("%s/%s" % (name, label), build(fr, baseline_ies(fr), fixed=fixed)))
    return frames


def load_plan(path):
    with open(path) as f:
        return json.load(f)


def write_corpus(frames, output, schema=None, write_labels=False):
    # Tags prefer schema-provided state/type/send_id (Spec-Reader-emitted) over the
    # built-in STATE_TYPE_MAP/SEND_ID_MAP, so handshake frames the LLM names from the
    # spec don't depend on a hardcoded family-name list.
    schema = schema or {}
    with open(output, "w") as f:
        for label, raw in frames:
            family = label.split("/", 1)[0]
            entry = schema.get(family, {})
            toks = []
            if entry.get("state") and entry.get("type"):
                st = (entry["state"], entry["type"])
            else:
                st = STATE_TYPE_MAP.get(family)
            if st:
                toks.append("@state=%s @type=%s" % st)
            sid = entry.get("send_id") or SEND_ID_MAP.get(family)
            if sid:
                toks.append("@send=%s" % sid)
            if toks:
                f.write("# " + " ".join(toks) + "\n")
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
        if isinstance(fr.get("qos"), str):       # data-frame QoS control octets
            fr["qos"] = bytes.fromhex(fr["qos"])
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
    write_corpus(frames, args.output, schema=schema, write_labels=args.labels)
    print("wrote %d frames -> %s" % (len(frames), args.output), file=sys.stderr)


if __name__ == "__main__":
    main()
