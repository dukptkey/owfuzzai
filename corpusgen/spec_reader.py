#!/usr/bin/env python3
"""Spec-Reader agent.

Reads IEEE 802.11 management-frame specification text and uses Claude to extract
a structured frame/IE schema that synthesizer.py consumes (and a human-readable
spec_notes.txt). One Claude call per frame family; the large spec text is sent as
a cached system prefix so repeat calls reuse it (verify via cache_read tokens).

Env: ANTHROPIC_API_KEY.   Install: pip install anthropic
Run:  python3 corpusgen/spec_reader.py --spec dot11_mgmt.txt --frames beacon,probe_request,authentication,assoc_request
Then: python3 corpusgen/synthesizer.py --schema schema.spec -o agent_corpus.txt
"""
import argparse
import json
import sys

DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_FRAMES = "beacon,probe_request,authentication,assoc_request"

SYSTEM_INSTRUCTIONS = (
    "You are a protocol-specification analyst. You read IEEE 802.11 specification text "
    "and produce a precise, machine-readable description of a SINGLE 802.11 management "
    "frame: its subtype, its fixed-field portion, and its information elements (IEs). "
    "Emit bytes as lowercase hex, no separators, no '0x', even number of digits. "
    "CRITICAL ENCODING RULE: for each IE, 'value' is ONLY the element's value/payload — "
    "do NOT include the 1-octet Element ID or the 1-octet Length; the downstream tool "
    "prepends those itself. Example: an SSID element for 'Home' has value '486f6d65' (the "
    "4 ASCII bytes), NOT '0004486f6d65'; a DS Parameter Set on channel 6 has value '06', "
    "NOT '030106'. Ground every field in the provided spec text; do NOT invent IEs the "
    "spec does not define for this frame."
)

# Structured-output schema for ONE frame family. The consumer (synthesizer.py) reads
# `subtype`, `fixed`, and `ies[].id` / `ies[].value`; the extra fields feed spec_notes
# and the future Tier-2 structured path. Structured outputs require additionalProperties:false.
FRAME_SCHEMA = {
    "type": "object",
    "properties": {
        "frame_name": {"type": "string"},
        "subtype": {"type": "integer"},
        "fixed": {"type": "string", "description": "baseline hex of the concatenated fixed fields in order, exact octet lengths, no IEs ('' if the frame has none)"},
        "ies": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "presence": {"type": "string", "description": "mandatory | optional | conditional"},
                    "value": {"type": "string", "description": "baseline hex of ONLY the IE value/payload — exclude the Element ID and Length octets ('' if the element value is empty)"},
                    "notes": {"type": "string"},
                },
                "required": ["id", "name", "presence", "value", "notes"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string"},
    },
    "required": ["frame_name", "subtype", "fixed", "ies", "notes"],
    "additionalProperties": False,
}


def build_system(spec_text):
    # Stable, cacheable prefix: fixed instructions + spec text. The cache_control marker
    # on the spec block caches instructions+spec together, reused across per-frame calls.
    return [
        {"type": "text", "text": SYSTEM_INSTRUCTIONS},
        {
            "type": "text",
            "text": "=== IEEE 802.11 SPECIFICATION EXCERPT ===\n" + spec_text,
            "cache_control": {"type": "ephemeral"},
        },
    ]


def clean_hex(value):
    """Validate/normalize an LLM-emitted hex string at the trust boundary."""
    s = "".join((value or "").split()).lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        return ""
    if len(s) % 2 != 0 or any(c not in "0123456789abcdef" for c in s):
        return None  # signal invalid
    return s


def extract_frame(client, model, system_blocks, frame_name):
    user = (
        f"Extract the schema for the 802.11 management frame: '{frame_name}'.\n"
        "Provide: the frame-control subtype (integer 0-15); the fixed-field portion as "
        "baseline hex ('fixed', '' if the frame has none); and the ordered list of IEs "
        "with id, name, presence (mandatory/optional/conditional), a baseline hex 'value' "
        "(PAYLOAD ONLY — no Element ID or Length octets, e.g. DS Parameter Set channel 6 is "
        "'06' not '030106'), and 'notes' (value ranges, constraints, and the spec clause). "
        "Summarize the frame and its state/usage in the top-level 'notes'."
    )
    resp = client.messages.create(
        model=model,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=system_blocks,
        messages=[{"role": "user", "content": user}],
        # effort (thinking depth) and format (schema enforcement) both live in output_config.
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": FRAME_SCHEMA}},
    )
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text), resp.usage


def normalize(frame_key, extracted):
    """Coerce one extraction into the synthesizer's schema entry + collect warnings."""
    warnings = []
    fixed = clean_hex(extracted.get("fixed", ""))
    if fixed is None:
        warnings.append(f"{frame_key}: invalid 'fixed' hex -> emptied")
        fixed = ""
    ies = []
    for ie in extracted.get("ies", []):
        eid = int(ie["id"])
        v = clean_hex(ie.get("value", ""))
        if v is None:
            warnings.append(f"{frame_key}: IE {eid} invalid hex -> emptied")
            v = ""
        # Guard: if the model still emitted the full element (id+len+payload) as the value
        # — detectable when value[0]==id and value[1]==payloadlen-2 — strip back to payload,
        # since the synthesizer prepends id+len itself.
        if v:
            vb = bytes.fromhex(v)
            if len(vb) >= 2 and vb[0] == (eid & 0xFF) and vb[1] == len(vb) - 2:
                warnings.append(f"{frame_key}: IE {eid} value included id+len; stripped to payload")
                v = vb[2:].hex()
        ies.append({
            "id": eid,
            "name": ie.get("name", ""),
            "presence": ie.get("presence", ""),
            "value": v,
        })
    entry = {"subtype": int(extracted["subtype"]), "fixed": fixed, "ies": ies}
    return entry, warnings


def render_notes(frame_key, extracted):
    lines = [f"## {frame_key} (subtype {extracted.get('subtype')})", extracted.get("notes", ""), ""]
    for ie in extracted.get("ies", []):
        lines.append(f"- IE {ie.get('id')} {ie.get('name')} [{ie.get('presence')}]: {ie.get('notes')}")
    lines.append("")
    return "\n".join(lines)


def run(args):
    import anthropic  # imported here so --self-test works without the package installed

    with open(args.spec) as f:
        spec_text = f.read()

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    system_blocks = build_system(spec_text)

    schema, notes_parts, warnings = {}, [], []
    for frame in [s.strip() for s in args.frames.split(",") if s.strip()]:
        extracted, usage = extract_frame(client, args.model, system_blocks, frame)
        entry, warns = normalize(frame, extracted)
        schema[frame] = entry
        warnings += warns
        notes_parts.append(render_notes(frame, extracted))
        print(
            "extracted %-16s ies=%d  (cache_read=%s cache_write=%s input=%s)"
            % (frame, len(entry["ies"]), usage.cache_read_input_tokens,
               usage.cache_creation_input_tokens, usage.input_tokens),
            file=sys.stderr,
        )

    write_outputs(schema, "\n".join(notes_parts), args.out, args.notes)
    for w in warnings:
        print("WARN: " + w, file=sys.stderr)
    print("wrote %d frame(s) -> %s ; notes -> %s" % (len(schema), args.out, args.notes), file=sys.stderr)


def write_outputs(schema, notes_text, out_path, notes_path):
    with open(out_path, "w") as f:
        json.dump(schema, f, indent=2)
    with open(notes_path, "w") as f:
        f.write(notes_text)


def self_test():
    """Offline: exercise the normalize/merge/write path with a canned extraction and
    confirm synthesizer.py can load and generate from the result. No API call."""
    canned = {
        "frame_name": "beacon",
        "subtype": 8,
        "fixed": "0000000000000000" + "6400" + "3104",
        "ies": [
            {"id": 0, "name": "SSID", "presence": "mandatory", "value": "6f7766757a7a6169", "notes": "<=32 bytes"},
            {"id": 1, "name": "Supported Rates", "presence": "mandatory", "value": "82848b96", "notes": "1-8 rates"},
            {"id": 3, "name": "DS Parameter Set", "presence": "optional", "value": "01", "notes": "current channel"},
        ],
        "notes": "Beacon announces a BSS.",
    }
    entry, warns = normalize("beacon", canned)
    assert entry["subtype"] == 8 and len(entry["ies"]) == 3 and not warns, (entry, warns)
    # invalid hex is caught
    bad, badwarns = normalize("x", {"subtype": 0, "fixed": "zz", "ies": []})
    assert bad["fixed"] == "" and badwarns, (bad, badwarns)
    # full-element value (id+len+payload) is stripped back to payload
    tlv, tlvwarns = normalize("y", {"subtype": 0, "fixed": "", "ies": [
        {"id": 3, "name": "DS", "presence": "optional", "value": "030106"}]})
    assert tlv["ies"][0]["value"] == "06" and tlvwarns, (tlv, tlvwarns)

    write_outputs({"beacon": entry}, render_notes("beacon", canned), "/tmp/_st_schema.spec", "/tmp/_st_notes.txt")

    import synthesizer  # sibling module (script dir is on sys.path)
    loaded = synthesizer.load_schema("/tmp/_st_schema.spec")
    frames = synthesizer.generate(loaded)
    assert frames and frames[0][1][0] == synthesizer.fc_byte0(8), "schema not synthesizer-compatible"
    print("self-test OK: %d frames synthesizable from extracted schema" % len(frames), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Spec-Reader: 802.11 spec text -> frame/IE schema via Claude")
    ap.add_argument("--spec", help="path to 802.11 management-frame spec text")
    ap.add_argument("--frames", default=DEFAULT_FRAMES, help="comma-separated frame families")
    ap.add_argument("--out", default="schema.spec", help="schema output (JSON content)")
    ap.add_argument("--notes", default="spec_notes.txt", help="natural-language notes output")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--self-test", action="store_true", help="run offline plumbing test (no API)")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not args.spec:
        ap.error("--spec is required (or use --self-test)")
    run(args)


if __name__ == "__main__":
    main()
