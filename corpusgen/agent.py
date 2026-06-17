#!/usr/bin/env python3
"""Agent protocol + shared Context for the multi-agent corpus-generation pipeline.

Each agent reads its input artifact(s) from the workspace and writes its output
artifact(s) — a Pipes-and-Filters design. The Orchestrator depends only on the
`Agent` protocol, so real agents and test fakes are interchangeable.
"""
import os
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Context:
    """Shared workspace state + config threaded through every agent."""
    workspace: str = "."
    spec: str = ""                       # input: 802.11 spec text path
    frames: list = field(default_factory=lambda: ["beacon", "probe_request", "authentication", "assoc_request"])
    model: str = "claude-opus-4-7"
    owfuzz_cmd: list = field(default_factory=list)  # base owfuzz argv; -p/-o appended by the substrate
    backend: str = "api"                 # "api" = Anthropic SDK (ANTHROPIC_API_KEY); "cli" = `claude -p`

    # artifact paths (resolved under workspace if relative)
    schema: str = "schema.spec"
    notes: str = "spec_notes.txt"
    corpus: str = "agent_corpus.txt"     # labels sidecar is <corpus>.labels
    results: str = "results.log"
    plan: str = "fuzz_plan.spec"
    report: str = "triage.txt"

    def __post_init__(self):
        for name in ("schema", "notes", "corpus", "results", "plan", "report"):
            v = getattr(self, name)
            if not os.path.isabs(v):
                setattr(self, name, os.path.join(self.workspace, v))


class Agent(Protocol):
    name: str

    def run(self, ctx: Context) -> None:
        ...
