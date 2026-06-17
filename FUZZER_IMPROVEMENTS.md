# owfuzz Fuzzer Improvements — capability log

Running log of every change made to the owfuzz substrate (the C fuzzer) and what
each one made possible, so the paper can trace engineering → capability → result.
Newest near the bottom. The agent layer (`corpusgen/`) is summarized at the end.

| # | Improvement (owfuzz / C) | What it enables | What it leveraged for the paper |
|---|--------------------------|-----------------|---------------------------------|
| 1 | **Corpus input + OTA results log + liveness crash detection** — `-p <corpus>` (overrides `poc.txt`), `-o <results.log>` per-frame TSV, beacon-liveness death detection (no target IP needed) | Replay an externally-generated corpus OTA and measure per-frame outcome/liveness | Decouples corpus *generation* (LLM agent layer) from the OTA *substrate*; gives the measurable feedback that closes the agent loop |
| 2 | **Frame-construction registry (Strategy pattern)** — `frames/frame_handler.{h,c}`, per-type self-registering `*_handler.c`, legacy switch fallback | Pluggable per-frame-type construction | Clean seam to slot corpus-backed construction in per type; extensibility |
| 3 | **Stateful corpus injection (Option A)** — `frames/corpus.{c,h}`, `next_fuzz_frame()` (corpus-first), `corpus_fixup_addrs()`, state-tagged corpus (`# @state/@type`), stall-watchdog | Inject fuzzed frames at the *matching point* of the interactive (`-T 1`) handshake, not just stateless `-T 0` replay | Reaches state-gated parser surfaces; the LLM tags each frame by protocol state |
| 4 | **Generic data-defined flow engine (Option B)** — `frames/flow.{c,h}`, `-F <flowfile>`, `@send` corpus ids, `flow_drive_reactive/spontaneous()` | Drive stateful handshakes whose states are **NOT hardcoded in owfuzz's C** — the flow is a data table, protocol-agnostic | The headline: the Spec-Reader emits the flow table + frames *from spec text*, so owfuzz drives flows it was never coded for (demonstrated: SAE offline; pivoting to WPA2 4-way OTA) |
| 5 | **WPA2 4-way / EAPOL support (corpusgen side done; owfuzz integration pending OTA)** — synthesizer data-frame encoding (ToDS + LLC/SNAP + EAPOL-Key body), 5 EAPOL-Key mutators, `fuzz:false` carrier frames; Spec-Reader emits the 5-state EAPOL flow from spec text; `llm_cli` JSON-repair (trailing commas) for the CLI backend | Drive open-auth → assoc → EAPOL entirely via the flow; fuzz the EAPOL-Key parser (M2). Verified offline: LLM flow + recon-grounded corpus consistent (`corpusgen/samples/eapol.flow` + `eapol_corpus.txt`) | Hits the real WPA2 attack surface (KRACK / FragAttacks / hostapd-EAPOL CVE territory) on a live AP. Demonstrates the chapter thesis: LLM owns the flow; OTA recon supplies target constants |
| 6 | **Optional credential-assisted crypto — `-K <psk>` (built)** — `frames/eapol_crypto.{c,h}`: self-contained SHA1/HMAC-SHA1/PBKDF2/PRF (vector-validated: SHA1 "abc" + canonical WPA `pbkdf2("password","IEEE")` PMK). On M1: stash ANonce; on sending M2/M4: derive PTK (PMK from `-K`+SSID), write SNonce + a valid key-descriptor-v2 MIC over the (fuzzed) frame. Hooked into `emit_flow_frame`/`flow_drive_reactive`; builds clean | Pass the MIC gate: valid M2 → AP sends M3 → fuzz post-MIC surface (GTK key-data, M3 decrypt) and M4 | A **code-coverage** mechanism: lifts the fuzzer past auth into the post-auth state machine (NOT an attack — user's own network/credential). Also flips our STA from the firmware-opaque pre-auth zone into the **host-observable** post-auth zone (rxhook). Honest split: LLM owns flow+structure; user supplies the secret; runtime fills the dynamic fields (SNonce, MIC) a static corpus can't |

## Target-side observability (rig instrumentation, not owfuzz itself)
- **`rxhook.ko`** — inline ARM detour of `asic_rx_pkt_process()`, the MT7915 RX funnel, on the closed Vivo router (driver static in `vmlinuz`, KPROBES disabled → hand-patched prologue; src `NOVO-ROUTER-VIVO/rx-hook`, deployed `/var/rxhook.ko`). Per received frame logs `skb/data/len/ring`; `dump=N` hexdumps ≤256 B as the driver sees it; sampling via `log_mask`; has an in-place frame-modify hook point.
  - **Use in the loop:** (1) confirm injected frames actually reach the driver parser (delivery ground truth, not OTA liveness); (2) crash attribution — last logged frame before death + `jean_kmsg`; (3) injection fidelity via `dump=`; (4) recon — hexdumps a real client's received M2/M4; (5) future: in-target fuzzing / coverage-ish feedback.
  - **Caveat:** firmware-specific (offsets hand-derived for Linux 4.4.115/ARM32/MT7915). White-box observability ⇒ per-target RE cost; the fuzzer still runs black-box without it.

## Scope boundaries (the honest walls — state these in the paper)
- **Transport** is hardcoded to 802.11-over-monitor-injection. "Arbitrary spec" therefore means any 802.11-carried protocol; a non-Wi-Fi target needs a new transport backend (vision tier).
- **Crypto gate.** Without `-K`, fuzzing reaches up to the first transition that needs a computed MIC/scalar (the pre-auth / parser surface where owfuzz's existing CVEs live). With `-K` (user-supplied credential) we cross that one gate for the 4-way handshake; the LLM still never invents crypto.

## Agent layer (`corpusgen/`, Python) — the other half of the system
- **Spec-Reader** (`spec_reader.py`): spec text → frame/IE schema (`FRAME_SCHEMA`) and, now, the stateful **flow table + handshake frames** (`FLOW_SCHEMA`, `--flow`). API + `claude` CLI (Max) backends.
- **Synthesizer** (`synthesizer.py`): schema → owfuzz corpus; IE + fixed-field + (adding) EAPOL-Key mutation operators; emits `@state/@type/@send` tags.
- **Triage** (`triage.py`): results.log → fuzz_plan (LLM-reasoned feedback).
- **Orchestrator** (`orchestrator.py`): runs the agent loop.
