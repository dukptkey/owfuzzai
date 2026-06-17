#!/usr/bin/env python3
"""Multi-agent fuzzing orchestrator.

Runs the loop: Spec-Reader (once) -> [ Synthesizer -> owfuzz (OTA) -> Feedback/Triage ]xN,
feeding each round's fuzz_plan back into the next Synthesizer round.

The Orchestrator depends only on the Agent protocol, so the real agents and the
test fakes are interchangeable (Dependency Inversion) — see --self-test, which
exercises the whole loop offline with fake LLM agents and a fake substrate.

Env: ANTHROPIC_API_KEY (real run).  Install: pip install anthropic
Off-rig run (no radio): --skip-substrate stops after the corpus so you can run
owfuzz manually, then re-run triage.
"""
import argparse
import os
import shlex
import sys

from agent import Context


class Orchestrator:
    def __init__(self, ctx, spec_reader, synthesizer, substrate, triage):
        self.ctx = ctx
        self.spec_reader = spec_reader
        self.synthesizer = synthesizer
        self.substrate = substrate
        self.triage = triage

    def _step(self, agent):
        print("[orchestrator] -> %s" % agent.name, file=sys.stderr)
        agent.run(self.ctx)

    def run(self, rounds=1, skip_substrate=False):
        self._step(self.spec_reader)  # once: spec -> schema
        for r in range(rounds):
            print("[orchestrator] round %d/%d" % (r + 1, rounds), file=sys.stderr)
            self._step(self.synthesizer)  # schema (+ fed-back plan) -> corpus
            if skip_substrate:
                print("[orchestrator] skip-substrate: run owfuzz to produce %s, then run triage.py"
                      % self.ctx.results, file=sys.stderr)
                return
            self._step(self.substrate)    # corpus -> results (OTA)
            self._step(self.triage)       # results -> fuzz_plan (fed back next round)


def build_real(ctx):
    import agents
    return Orchestrator(ctx, agents.SpecReaderAgent(), agents.SynthesizerAgent(),
                        agents.OwfuzzSubstrate(), agents.TriageAgent())


def self_test():
    """Offline proof of the loop + feedback: fake LLM agents and a fake substrate,
    real Synthesizer. Orchestrator code is identical to the real run; only the
    injected implementations differ."""
    import json
    import shutil
    import synthesizer
    import agents

    ws = "/tmp/_orch"
    shutil.rmtree(ws, ignore_errors=True)
    os.makedirs(ws)
    ctx = Context(workspace=ws, spec="(none)", frames=["beacon", "authentication"])

    def file_schema():  # sample_schema() holds bytes; the on-disk contract is hex strings
        out = {}
        for name, fr in synthesizer.sample_schema().items():
            out[name] = {"subtype": fr["subtype"], "fixed": fr["fixed"].hex(),
                         "ies": [{"id": e["id"], "value": e["value"].hex()} for e in fr["ies"]]}
        return out

    class FakeSpecReader:
        name = "fake-spec-reader"
        def run(self, ctx):
            json.dump(file_schema(), open(ctx.schema, "w"))
            open(ctx.notes, "w").write("notes")

    class FakeSubstrate:
        name = "fake-substrate"
        def run(self, ctx):
            rows = [l.rstrip("\n").split("\t") for l in open(ctx.corpus + ".labels") if not l.startswith("#")]
            with open(ctx.results, "w") as f:
                f.write("# ts_ms\tidx\tfc_type\tfc_subtype\tlen\talive\tpoc\n")
                for i, (idx, _label, ln) in enumerate(rows):
                    alive = 0 if i == 1 else 1   # pretend the 2nd frame crashes the target
                    f.write("%d\t%s\t0\t0x00\t%s\t%d\t%s\n" % (1000 + i, idx, ln, alive, "poc.pcap" if alive == 0 else "-"))

    class FakeTriage:
        name = "fake-triage"
        def run(self, ctx):
            labels = {l.split("\t")[0]: l.split("\t")[1] for l in open(ctx.corpus + ".labels") if not l.startswith("#")}
            crash_idx = next(r.split("\t")[1] for r in open(ctx.results) if not r.startswith("#") and r.split("\t")[5] == "0")
            fam = labels[crash_idx].split("/")[0]
            json.dump({"focus_frames": [fam], "focus_mutations": [], "drop_frames": [], "rationale": "fake"},
                      open(ctx.plan, "w"))

    orch = Orchestrator(ctx, FakeSpecReader(), agents.SynthesizerAgent(), FakeSubstrate(), FakeTriage())
    orch.run(rounds=2)

    plan = synthesizer.load_plan(ctx.plan)
    fams = {l.split("\t")[1].split("/")[0] for l in open(ctx.corpus + ".labels") if not l.startswith("#")}
    assert plan["focus_frames"] and fams == set(plan["focus_frames"]), (fams, plan["focus_frames"])
    print("self-test OK: 2 rounds ran; round-2 corpus focused to %s via the fed-back plan" % fams, file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Multi-agent fuzzing orchestrator")
    ap.add_argument("--workspace", default=".")
    ap.add_argument("--spec")
    ap.add_argument("--frames", default="beacon,probe_request,authentication,assoc_request")
    ap.add_argument("--model", default="claude-opus-4-7")
    ap.add_argument("--owfuzz", help="base owfuzz command (quoted); -p/-o are appended")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--skip-substrate", action="store_true", help="stop after corpus (run owfuzz manually)")
    ap.add_argument("--backend", choices=["api", "cli"], default="api",
                    help="api = Anthropic SDK (ANTHROPIC_API_KEY); cli = `claude -p` (Max subscription)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not args.spec:
        ap.error("--spec is required (or use --self-test)")
    ctx = Context(
        workspace=args.workspace,
        spec=args.spec,
        frames=[s.strip() for s in args.frames.split(",") if s.strip()],
        model=args.model,
        owfuzz_cmd=shlex.split(args.owfuzz) if args.owfuzz else [],
        backend=args.backend,
    )
    build_real(ctx).run(rounds=args.rounds, skip_substrate=args.skip_substrate)


if __name__ == "__main__":
    main()
