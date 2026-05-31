#!/usr/bin/env python3
"""Feedback/Triage agent.

Reads owfuzz's results.log (TSV) + the corpus .labels sidecar, aggregates the
campaign deterministically, then uses Claude (LLM-reasoned triage) to interpret
the outcome and emit:
  - fuzz_plan.spec : which frames/mutations to focus next (consumed by synthesizer --plan)
  - triage.txt     : human-readable findings + crash analysis

Closes the loop: Spec-Reader -> Synthesizer -> owfuzz -> Feedback/Triage -> (re-plan).

Env: ANTHROPIC_API_KEY.  Install: pip install anthropic
Run:  python3 corpusgen/triage.py --results results.log --labels agent_corpus.txt.labels
"""
import argparse
import json
import sys
from collections import Counter

DEFAULT_MODEL = "claude-opus-4-7"

SYSTEM_INSTRUCTIONS = (
    "You are a Wi-Fi (IEEE 802.11) fuzzing triage analyst. You are given a deterministic "
    "summary of one over-the-air fuzzing campaign in which owfuzz replayed an agent-generated "
    "corpus of management frames against a real device. 'alive=0' means the target stopped "
    "responding after that frame (a likely crash/DoS). Your job: triage the outcome and decide "
    "what the corpus generator should focus on next to deepen coverage and confirm/expand on any "
    "crash. Be concrete and ground every claim in the provided data; do not invent frames that "
    "were not exercised."
)

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "severity": {"type": "string", "description": "crash | anomaly | info"},
                    "summary": {"type": "string"},
                },
                "required": ["label", "severity", "summary"],
                "additionalProperties": False,
            },
        },
        "crash_analysis": {"type": "string"},
        "next_plan": {
            "type": "object",
            "properties": {
                "focus_frames": {"type": "array", "items": {"type": "string"}},
                "focus_mutations": {"type": "array", "items": {"type": "string"}},
                "drop_frames": {"type": "array", "items": {"type": "string"}},
                "rationale": {"type": "string"},
            },
            "required": ["focus_frames", "focus_mutations", "drop_frames", "rationale"],
            "additionalProperties": False,
        },
    },
    "required": ["findings", "crash_analysis", "next_plan"],
    "additionalProperties": False,
}


def parse_results(results_path, labels_path):
    labels = {}
    if labels_path:
        for line in open(labels_path):
            if line.startswith("#") or not line.strip():
                continue
            idx, label, _len = line.rstrip("\n").split("\t")
            labels[int(idx)] = label
    records = []
    for line in open(results_path):
        if line.startswith("#") or not line.strip():
            continue
        ts, idx, fc_t, fc_st, ln, alive, poc = line.rstrip("\n").split("\t")
        idx = int(idx)
        records.append({
            "idx": idx,
            "label": labels.get(idx, "idx_%d" % idx),
            "fc_type": int(fc_t),
            "fc_subtype": int(fc_st, 16) if fc_st.startswith("0x") else int(fc_st),
            "len": int(ln),
            "alive": int(alive),
            "poc": poc,
        })
    return records


def family(label):
    return label.split("/", 1)[0]


def mutation(label):
    return label.split("/", 1)[1] if "/" in label else "baseline"


def summarize(records):
    fam_counts = Counter(family(r["label"]) for r in records)
    mut_counts = Counter(mutation(r["label"]) for r in records)
    crash = next((r for r in records if r["alive"] == 0), None)
    summary = {
        "total_frames": len(records),
        "families": dict(fam_counts),
        "mutations": dict(mut_counts),
        "crash": {"idx": crash["idx"], "label": crash["label"], "poc": crash["poc"]} if crash else None,
    }
    lines = [
        "Total frames replayed: %d" % len(records),
        "Frame families exercised: " + ", ".join("%s=%d" % (k, v) for k, v in sorted(fam_counts.items())),
        "Mutations exercised: " + ", ".join("%s=%d" % (k, v) for k, v in sorted(mut_counts.items())),
    ]
    if crash:
        lines.append("CRASH: target went silent after idx %d (%s); poc=%s"
                     % (crash["idx"], crash["label"], crash["poc"]))
    else:
        lines.append("No crash observed (target stayed alive for all frames).")
    lines.append("")
    lines.append("Per-frame outcomes (idx, label, len, alive):")
    for r in records:
        lines.append("  %d\t%s\tlen=%d\talive=%d" % (r["idx"], r["label"], r["len"], r["alive"]))
    return summary, "\n".join(lines)


def build_system(spec_notes):
    blocks = [{"type": "text", "text": SYSTEM_INSTRUCTIONS}]
    if spec_notes:
        blocks.append({"type": "text", "text": "=== SPEC NOTES (context) ===\n" + spec_notes})
    blocks[-1]["cache_control"] = {"type": "ephemeral"}  # cache the stable prefix
    return blocks


def triage_user_prompt(summary_text):
    return (
        "Here is the campaign summary:\n\n" + summary_text + "\n\n"
        "Produce: (1) findings (one per notable frame, severity crash|anomaly|info); "
        "(2) crash_analysis (root-cause hypothesis grounded in the frame/mutation that "
        "triggered it, or why nothing crashed); (3) next_plan — focus_frames and "
        "focus_mutations to emphasize next, drop_frames to stop wasting budget on, and a "
        "rationale. Use the exact frame-family and mutation names seen in the summary."
    )


def triage_llm(client, model, system_blocks, summary_text):
    user = triage_user_prompt(summary_text)
    resp = client.messages.create(
        model=model,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        system=system_blocks,
        messages=[{"role": "user", "content": user}],
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": PLAN_SCHEMA}},
    )
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text)


def write_outputs(triage, summary_text, plan_path, report_path):
    with open(plan_path, "w") as f:
        json.dump(triage["next_plan"], f, indent=2)
    with open(report_path, "w") as f:
        f.write("# Fuzzing Triage Report\n\n## Crash analysis\n")
        f.write(triage.get("crash_analysis", "") + "\n\n## Findings\n")
        for fnd in triage.get("findings", []):
            f.write("- [%s] %s: %s\n" % (fnd["severity"], fnd["label"], fnd["summary"]))
        f.write("\n## Next plan\n")
        f.write(json.dumps(triage["next_plan"], indent=2) + "\n\n## Raw campaign summary\n")
        f.write(summary_text + "\n")


def run(args):
    records = parse_results(args.results, args.labels)
    if not records:
        print("no records parsed from %s" % args.results, file=sys.stderr)
        return
    summary, summary_text = summarize(records)
    spec_notes = open(args.notes).read() if args.notes else ""

    if args.backend == "api":
        import anthropic  # lazy so --self-test needs no package/key
        client = anthropic.Anthropic()
        triage = triage_llm(client, args.model, build_system(spec_notes), summary_text)
    else:
        import llm_cli  # subscription-backed claude CLI dispatch
        system_text = SYSTEM_INSTRUCTIONS + (("\n\n=== SPEC NOTES (context) ===\n" + spec_notes) if spec_notes else "")
        triage = llm_cli.complete_json(system_text, triage_user_prompt(summary_text), PLAN_SCHEMA)

    write_outputs(triage, summary_text, args.plan_out, args.report_out)
    crash = summary["crash"]
    print("triaged %d frames; crash=%s -> %s ; report -> %s"
          % (summary["total_frames"], crash["label"] if crash else "none",
             args.plan_out, args.report_out), file=sys.stderr)


def self_test():
    """Offline: canned results.log + labels -> parse/aggregate -> deterministic plan ->
    confirm synthesizer --plan consumes it. No API call."""
    labels = "# idx\tlabel\tlen\n0\tbeacon/baseline\t57\n1\tauthentication/baseline\t30\n2\tauthentication/len_overflow\t30\n"
    results = ("# ts_ms\tidx\tfc_type\tfc_subtype\tlen\talive\tpoc\n"
               "1000\t0\t0\t0x08\t57\t1\t-\n"
               "1010\t1\t0\t0x0b\t30\t1\t-\n"
               "1020\t2\t0\t0x0b\t30\t0\tpoc.pcap\n")
    open("/tmp/_tr_labels", "w").write(labels)
    open("/tmp/_tr_results", "w").write(results)

    records = parse_results("/tmp/_tr_results", "/tmp/_tr_labels")
    assert len(records) == 3, records
    summary, text = summarize(records)
    assert summary["crash"]["label"] == "authentication/len_overflow", summary

    # Deterministic plan (what the LLM would refine): focus the crashing family + mutation.
    plan = {
        "focus_frames": [family(summary["crash"]["label"])],
        "focus_mutations": [mutation(summary["crash"]["label"]), "oversized_value"],
        "drop_frames": ["beacon"],
        "rationale": "self-test",
    }
    json.dump(plan, open("/tmp/_tr_plan.spec", "w"))

    import synthesizer
    schema = synthesizer.sample_schema()
    loaded_plan = synthesizer.load_plan("/tmp/_tr_plan.spec")
    frames = synthesizer.generate(schema, loaded_plan)
    fams = {f.split("/", 1)[0] for f, _ in frames}
    assert fams == {"authentication"}, fams  # focus_frames honored, beacon dropped
    muts = {f.split("/", 1)[1] for f, _ in frames}
    assert muts <= {"baseline", "len_overflow", "oversized_value"}, muts  # focus_mutations honored
    print("self-test OK: plan parsed, synthesizer focused to %s (%d frames)" % (fams, len(frames)), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Feedback/Triage agent: results.log -> fuzz_plan + report")
    ap.add_argument("--results", help="owfuzz results.log (TSV)")
    ap.add_argument("--labels", help="corpus .labels sidecar (idx -> frame label)")
    ap.add_argument("--notes", help="spec_notes.txt for context (optional, cached)")
    ap.add_argument("--plan-out", default="fuzz_plan.spec", dest="plan_out")
    ap.add_argument("--report-out", default="triage.txt", dest="report_out")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="API backend model (ignored by --backend cli)")
    ap.add_argument("--backend", choices=["api", "cli"], default="api",
                    help="api = Anthropic SDK (ANTHROPIC_API_KEY); cli = `claude -p` (Max subscription)")
    ap.add_argument("--self-test", action="store_true", help="run offline plumbing test (no API)")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not args.results:
        ap.error("--results is required (or use --self-test)")
    run(args)


if __name__ == "__main__":
    main()
