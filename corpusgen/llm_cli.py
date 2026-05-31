#!/usr/bin/env python3
"""Subscription-backed LLM dispatch via the `claude -p` CLI.

Lets the Spec-Reader / Triage agents run on a Claude Code (Max) subscription
instead of a metered ANTHROPIC_API_KEY. Same prompts; since the CLI has no
server-side json_schema enforcement, the schema is handed to the model in the
prompt and the response is parsed/validated here. Selected with --backend cli.
"""
import json
import subprocess


def _extract_result(stdout):
    # `claude -p --output-format json` returns either the final result object or
    # the full event list; in both cases the result text lives in a {type:result} entry.
    data = json.loads(stdout)
    if isinstance(data, list):
        result = next(e for e in reversed(data) if e.get("type") == "result")
        return result["result"]
    return data["result"] if isinstance(data, dict) and "result" in data else stdout


def _strip_fences(text):
    t = text.strip()
    if t.startswith("```"):
        nl = t.find("\n")
        t = t[nl + 1:] if nl != -1 else t
        end = t.rfind("```")
        if end != -1:
            t = t[:end]
    return t.strip()


def complete_json(system_text, user_text, schema, model=None, timeout=600):
    """Run one prompt through the claude CLI and return the parsed JSON object."""
    prompt = (
        system_text + "\n\n" + user_text + "\n\n"
        "Respond with a SINGLE JSON object and nothing else — no markdown fences, no "
        "commentary, no tool use. Everything you need is in this prompt. The object MUST "
        "validate against this JSON Schema:\n" + json.dumps(schema)
    )
    cmd = ["claude", "-p", "--output-format", "json"]
    if model:
        cmd += ["--model", model]
    proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError("claude CLI failed (%d): %s" % (proc.returncode, proc.stderr[:500]))
    return json.loads(_strip_fences(_extract_result(proc.stdout)))
