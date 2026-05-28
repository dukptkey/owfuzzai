#!/usr/bin/env python3
"""Concrete agents implementing the Agent protocol.

Each class composes the already-tested functions in spec_reader / synthesizer /
triage; no logic is duplicated and the standalone CLIs are untouched. LLM clients
are created lazily (and injectable) so importing this module needs no API key.
"""
import os

import spec_reader
import synthesizer
import triage


class SpecReaderAgent:
    name = "spec-reader"

    def __init__(self, client=None):
        self.client = client

    def run(self, ctx):
        import anthropic
        client = self.client or anthropic.Anthropic()
        spec_text = open(ctx.spec).read()
        system = spec_reader.build_system(spec_text)
        schema, notes = {}, []
        for frame in ctx.frames:
            extracted, _ = spec_reader.extract_frame(client, ctx.model, system, frame)
            entry, _ = spec_reader.normalize(frame, extracted)
            schema[frame] = entry
            notes.append(spec_reader.render_notes(frame, extracted))
        spec_reader.write_outputs(schema, "\n".join(notes), ctx.schema, ctx.notes)


class SynthesizerAgent:
    name = "synthesizer"

    def run(self, ctx):
        schema = synthesizer.load_schema(ctx.schema)
        plan = synthesizer.load_plan(ctx.plan) if os.path.exists(ctx.plan) else None
        frames = synthesizer.generate(schema, plan)
        synthesizer.write_corpus(frames, ctx.corpus, write_labels=True)


class OwfuzzSubstrate:
    """Thin execution substrate: replays the corpus over the air via owfuzz."""
    name = "owfuzz"

    def run(self, ctx):
        import subprocess
        if not ctx.owfuzz_cmd:
            raise RuntimeError("no owfuzz command configured (pass --owfuzz)")
        cmd = list(ctx.owfuzz_cmd) + ["-p", ctx.corpus, "-o", ctx.results]
        subprocess.run(cmd, check=True)


class TriageAgent:
    name = "triage"

    def __init__(self, client=None):
        self.client = client

    def run(self, ctx):
        import anthropic
        client = self.client or anthropic.Anthropic()
        records = triage.parse_results(ctx.results, ctx.corpus + ".labels")
        _summary, text = triage.summarize(records)
        spec_notes = open(ctx.notes).read() if os.path.exists(ctx.notes) else ""
        result = triage.triage_llm(client, ctx.model, triage.build_system(spec_notes), text)
        triage.write_outputs(result, text, ctx.plan, ctx.report)
