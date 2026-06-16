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
    "NOT '030106'. Ground the frame STRUCTURE — which IEs exist, their order, the fixed "
    "fields — strictly in the provided spec text; do NOT invent IEs the spec does not "
    "define for this frame. But for each IE that IS present, ALWAYS supply a "
    "representative, spec-valid baseline 'value' (e.g. a plausible SSID '6f7766757a7a6169', "
    "a full Supported Rates set, the DS channel byte) even when the spec describes the "
    "field abstractly instead of giving literal bytes; emit '' ONLY when the element "
    "genuinely carries no payload (a flag/marker-only element)."
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
                    "value": {"type": "string", "description": "representative baseline hex of ONLY the IE value/payload — exclude the Element ID and Length octets; supply a plausible spec-valid example even if the spec is abstract, '' only for genuinely payload-less elements"},
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


# Structured-output schema for a stateful HANDSHAKE: the frames the STA sends plus the
# transition table driving them. This is what makes the flow itself spec-derived (Option B)
# rather than hardcoded in owfuzz's C. `frames[]` reuse the per-frame shape (+ send_id);
# `transitions[]` render to the pipe-delimited .flow format owfuzz/src/frames/flow.c parses.
FLOW_FRAME_ITEM = {
    "type": "object",
    "properties": {
        "frame_name": {"type": "string"},
        "send_id": {"type": "string", "description": "short stable id reused verbatim in transitions[].send"},
        "subtype": {"type": "integer"},
        "type": {"type": "string", "description": "802.11 frame type name, e.g. AUTH"},
        "fixed": {"type": "string", "description": "baseline hex of the concatenated fixed fields in order ('' if none)"},
        "ies": FRAME_SCHEMA["properties"]["ies"],
        "notes": {"type": "string"},
    },
    "required": ["frame_name", "send_id", "subtype", "type", "fixed", "ies", "notes"],
    "additionalProperties": False,
}

FLOW_SCHEMA = {
    "type": "object",
    "properties": {
        "handshake": {"type": "string"},
        "frames": {"type": "array", "items": FLOW_FRAME_ITEM},
        "transitions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "in_state": {"type": "string"},
                    "on_rx": {"type": "string", "description": "'START' (fires on entering in_state, no rx) or an 802.11 type NAME of the frame that must be received, e.g. AUTH"},
                    "match_offset": {"type": "integer", "description": "octet offset FROM FRAME START (the 24-byte MAC header is included, so the body begins at offset 24) of a byte to match in the received frame; -1 for no byte predicate"},
                    "match_byte": {"type": "string", "description": "the required byte at match_offset as exactly 2 hex digits, '' when match_offset is -1"},
                    "send": {"type": "string", "description": "send_id of the frame to transmit when this rule fires, or '' to send nothing"},
                    "goto_state": {"type": "string"},
                    "notes": {"type": "string"},
                },
                "required": ["in_state", "on_rx", "match_offset", "match_byte", "send", "goto_state", "notes"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string"},
    },
    "required": ["handshake", "frames", "transitions", "notes"],
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


def frame_user_prompt(frame_name):
    return (
        f"Extract the schema for the 802.11 management frame: '{frame_name}'.\n"
        "Provide: the frame-control subtype (integer 0-15); the fixed-field portion as "
        "baseline hex ('fixed', '' if the frame has none); and the ordered list of IEs "
        "with id, name, presence (mandatory/optional/conditional), a representative baseline "
        "hex 'value' (PAYLOAD ONLY — no Element ID or Length octets, e.g. DS Parameter Set "
        "channel 6 is '06' not '030106'; supply a plausible spec-valid example even when the "
        "spec is abstract, '' only for genuinely payload-less elements), and 'notes' (value "
        "ranges, constraints, and the spec clause). "
        "Summarize the frame and its state/usage in the top-level 'notes'."
    )


def extract_frame(client, model, system_blocks, frame_name):
    user = frame_user_prompt(frame_name)
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


def flow_user_prompt(handshake):
    return (
        f"From the specification text, extract the message-exchange STATE MACHINE for the "
        f"{handshake} handshake, with owfuzz acting as the initiating station (STA) that "
        "fuzzes the peer/AP. Produce TWO coordinated outputs:\n"
        "1) 'frames': every distinct frame the STA SENDS during the handshake, each as a frame "
        "schema — frame_name, a short stable 'send_id' (reused VERBATIM in the transitions' "
        "'send' column), the 802.11 frame subtype (integer) and 'type' NAME (e.g. AUTH), the "
        "fixed-field portion as baseline hex, and any IEs (PAYLOAD-ONLY values per the rules "
        "above). For SAE these are Authentication frames (type AUTH, subtype 11) whose body "
        "carries the SAE algorithm number, transaction sequence, status, and the group/scalar/"
        "element (commit) or send-confirm/confirm (confirm) fields — put the whole body in "
        "'fixed' with no IEs.\n"
        "2) 'transitions': the ordered rules that drive the handshake. Each rule = (in_state, "
        "on_rx, match_offset, match_byte, send, goto_state). 'on_rx' is the literal 'START' for "
        "a rule that fires spontaneously on entering in_state (no received frame), otherwise the "
        "802.11 type NAME of the frame that must be received to fire the rule. 'match_offset' is "
        "an octet offset FROM THE FRAME START — the 24-octet MAC header is included, so the frame "
        "BODY begins at offset 24; use it with 'match_byte' (2 hex digits) to require a specific "
        "byte in the received frame (e.g. the SAE algorithm low byte 0x03 sits at offset 24), or "
        "set match_offset=-1 and match_byte='' for no byte predicate. 'send' = the send_id of the "
        "frame to transmit, or '' to send nothing. 'goto_state' = the next state.\n"
        "Use INIT as the entry (start) state and DONE as the terminal state; keep state names "
        "short UPPER_SNAKE_CASE. Summarize the handshake in the top-level 'notes'."
    )


def extract_flow(client, model, system_blocks, handshake):
    resp = client.messages.create(
        model=model,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=system_blocks,
        messages=[{"role": "user", "content": flow_user_prompt(handshake)}],
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": FLOW_SCHEMA}},
    )
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text), resp.usage


def render_flow(extracted):
    """Render an extracted flow into the pipe-delimited text owfuzz/src/frames/flow.c parses:
    `in_state | on_rx[ match=OFF:HH] | send|- | goto_state`."""
    lines = [
        "# %s flow — generated by spec_reader from spec text." % extracted.get("handshake", "handshake"),
        "# owfuzz drives these states (NOT hardcoded in its C); frames come from the -p corpus",
        "# by @send id. on_rx 'TYPE match=OFF:HH' = a received TYPE frame whose byte at offset OFF",
        "# (from frame start, MAC header included) == 0xHH.",
        "#",
        "# in_state    | on_rx            | send        | goto_state",
    ]
    for t in extracted.get("transitions", []):
        onrx = (t.get("on_rx") or "START").strip()
        if onrx != "START":
            off = int(t.get("match_offset", -1))
            mb = clean_hex(t.get("match_byte", ""))
            if off >= 0 and mb:
                onrx = "%s match=%d:%s" % (onrx, off, mb)
        send = (t.get("send") or "").strip() or "-"
        lines.append("%-13s | %-16s | %-11s | %s" % (
            t["in_state"].strip(), onrx, send, t["goto_state"].strip()))
    return "\n".join(lines) + "\n"


def merge_flow_frames(schema, extracted):
    """Normalize the handshake frames into the schema (keyed by frame_name, carrying send_id),
    and validate that every transition's 'send' references a frame. Returns warnings."""
    warnings = []
    send_ids = set()
    for fr in extracted.get("frames", []):
        name = fr.get("frame_name") or fr.get("send_id")
        fr.setdefault("send_id", name)
        entry, warns = normalize(name, fr)
        entry.setdefault("send_id", fr["send_id"])
        schema[name] = entry
        send_ids.add(entry["send_id"])
        warnings += warns
    for t in extracted.get("transitions", []):
        s = (t.get("send") or "").strip()
        if s and s not in send_ids:
            warnings.append("flow: transition send '%s' has no matching frame send_id" % s)
    return warnings


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
    # Handshake-frame extras (flow path): the send id that ties this frame to a flow
    # rule's `send` column, plus optional corpus state/type tags. Absent on the normal
    # per-family path, so they only appear when the model supplies them.
    for k in ("send_id", "state", "type"):
        v = extracted.get(k)
        if v:
            entry[k] = v
    return entry, warnings


def render_notes(frame_key, extracted):
    lines = [f"## {frame_key} (subtype {extracted.get('subtype')})", extracted.get("notes", ""), ""]
    for ie in extracted.get("ies", []):
        lines.append(f"- IE {ie.get('id')} {ie.get('name')} [{ie.get('presence')}]: {ie.get('notes')}")
    lines.append("")
    return "\n".join(lines)


def run(args):
    with open(args.spec) as f:
        spec_text = f.read()

    if args.backend == "api":
        import anthropic  # imported here so --self-test works without the package installed
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        system_blocks = build_system(spec_text)
    else:
        import llm_cli  # subscription-backed claude CLI dispatch
        system_text = SYSTEM_INSTRUCTIONS + "\n\n=== IEEE 802.11 SPECIFICATION EXCERPT ===\n" + spec_text

    schema, notes_parts, warnings = {}, [], []
    for frame in [s.strip() for s in args.frames.split(",") if s.strip()]:
        if args.backend == "api":
            extracted, usage = extract_frame(client, args.model, system_blocks, frame)
            meta = "cache_read=%s cache_write=%s input=%s" % (
                usage.cache_read_input_tokens, usage.cache_creation_input_tokens, usage.input_tokens)
        else:
            extracted = llm_cli.complete_json(system_text, frame_user_prompt(frame), FRAME_SCHEMA)
            meta = "via claude CLI"
        entry, warns = normalize(frame, extracted)
        schema[frame] = entry
        warnings += warns
        notes_parts.append(render_notes(frame, extracted))
        print("extracted %-16s ies=%d  (%s)" % (frame, len(entry["ies"]), meta), file=sys.stderr)

    if args.flow:
        if args.backend == "api":
            flow_extracted, usage = extract_flow(client, args.model, system_blocks, args.handshake)
            meta = "cache_read=%s input=%s" % (usage.cache_read_input_tokens, usage.input_tokens)
        else:
            flow_extracted = llm_cli.complete_json(system_text, flow_user_prompt(args.handshake), FLOW_SCHEMA)
            meta = "via claude CLI"
        warnings += merge_flow_frames(schema, flow_extracted)
        with open(args.flow, "w") as f:
            f.write(render_flow(flow_extracted))
        notes_parts.append("## flow: %s\n%s\n" % (args.handshake, flow_extracted.get("notes", "")))
        print("extracted flow %-12s frames=%d transitions=%d -> %s  (%s)" % (
            args.handshake, len(flow_extracted.get("frames", [])),
            len(flow_extracted.get("transitions", [])), args.flow, meta), file=sys.stderr)

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

    # --- flow path (Option B): merge handshake frames + render the .flow, offline ---
    flow_canned = {
        "handshake": "WPA3 SAE commit/confirm",
        "frames": [
            {"frame_name": "sae_commit", "send_id": "sae_commit", "subtype": 11, "type": "AUTH",
             "fixed": "0300010000001300" + "11" * 96, "ies": [], "notes": "SAE commit"},
            {"frame_name": "sae_confirm", "send_id": "sae_confirm", "subtype": 11, "type": "AUTH",
             "fixed": "030002000000" + "33" * 32, "ies": [], "notes": "SAE confirm"},
        ],
        "transitions": [
            {"in_state": "INIT", "on_rx": "START", "match_offset": -1, "match_byte": "",
             "send": "sae_commit", "goto_state": "COMMIT_SENT", "notes": "send commit on entry"},
            {"in_state": "COMMIT_SENT", "on_rx": "AUTH", "match_offset": 24, "match_byte": "03",
             "send": "sae_confirm", "goto_state": "CONFIRM_SENT", "notes": "AP commit reply"},
            {"in_state": "CONFIRM_SENT", "on_rx": "AUTH", "match_offset": 24, "match_byte": "03",
             "send": "", "goto_state": "DONE", "notes": "AP confirm"},
        ],
        "notes": "SAE small-group commit/confirm.",
    }
    flow_schema = {}
    fwarns = merge_flow_frames(flow_schema, flow_canned)
    assert not fwarns, fwarns
    assert flow_schema["sae_commit"]["send_id"] == "sae_commit", flow_schema
    # an undefined send is flagged
    assert merge_flow_frames({}, {"frames": [], "transitions": [
        {"in_state": "INIT", "on_rx": "START", "match_offset": -1, "match_byte": "",
         "send": "ghost", "goto_state": "X", "notes": ""}]}), "undefined send not flagged"
    rendered = render_flow(flow_canned)
    # the byte predicate renders in flow.c's OFF:HH form, and the spontaneous rule has no match=
    assert "AUTH match=24:03" in rendered, rendered
    rule_lines = [l for l in rendered.splitlines() if l and not l.startswith("#")]
    assert len(rule_lines) == 3 and rule_lines[0].split("|")[1].strip() == "START", rule_lines

    # synthesizer emits @send from the schema-provided send_id (no hardcoded name dependency)
    write_outputs(flow_schema, "", "/tmp/_st_sae_schema.spec", "/tmp/_st_sae_notes.txt")
    sae_loaded = synthesizer.load_schema("/tmp/_st_sae_schema.spec")
    synthesizer.write_corpus(synthesizer.generate(sae_loaded), "/tmp/_st_sae_corpus.txt", schema=sae_loaded)
    with open("/tmp/_st_sae_corpus.txt") as f:
        corpus_txt = f.read()
    assert "@send=sae_commit" in corpus_txt and "@send=sae_confirm" in corpus_txt, corpus_txt

    print("self-test OK: %d frames synthesizable; flow renders %d rules + @send corpus"
          % (len(frames), len(rule_lines)), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Spec-Reader: 802.11 spec text -> frame/IE schema via Claude")
    ap.add_argument("--spec", help="path to 802.11 management-frame spec text")
    ap.add_argument("--frames", default=DEFAULT_FRAMES, help="comma-separated frame families ('' to skip and do flow only)")
    ap.add_argument("--flow", help="also extract a stateful handshake flow -> this .flow file (Option B)")
    ap.add_argument("--handshake", default="WPA3 SAE commit/confirm", help="handshake to extract for --flow")
    ap.add_argument("--out", default="schema.spec", help="schema output (JSON content)")
    ap.add_argument("--notes", default="spec_notes.txt", help="natural-language notes output")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="API backend model (ignored by --backend cli)")
    ap.add_argument("--backend", choices=["api", "cli"], default="api",
                    help="api = Anthropic SDK (ANTHROPIC_API_KEY); cli = `claude -p` (Max subscription)")
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
