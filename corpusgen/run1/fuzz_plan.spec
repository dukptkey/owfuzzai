{
  "focus_frames": [
    "authentication",
    "assoc_request",
    "beacon"
  ],
  "focus_mutations": [
    "missing_mandatory",
    "dup_ie",
    "reserved_ie",
    "len_overflow",
    "oversized_value"
  ],
  "drop_frames": [
    "probe_request"
  ],
  "rationale": "Three concrete pivots grounded in this summary: (1) Fix and re-prioritize len_overflow and oversized_value \u2014 across all 4 frame families their on-air length equals the baseline (beacon 56, probe_request 30, authentication 32, assoc_request 37), meaning the IE length-byte / value-size mutation is not actually emitted; this is the highest-leverage gap because length-field abuse on IEs (e.g., IE 0 SSID len=0xFF with no payload, IE 48 RSN len > frame remainder, IE 1 Rates len=0) is historically where 802.11 parsers fail. Once they actually mutate, re-run focused on beacon (IE 0/1/48/50) and assoc_request (IE 0/1/48/127). (2) Deepen authentication coverage: authentication/missing_mandatory currently truncates by exactly 2 bytes (len 30 vs 32) and authentication/dup_ie injects an IE into a frame that per spec carries none outside Shared-Key \u2014 vary which fixed field is truncated (Algorithm vs Seq vs Status), set Algorithm to 1 (Shared Key) or 3 (SAE) with seq=2/3 and include/omit IE 16 Challenge Text with extreme lengths, and inject IE 16 into Open-System auth where it is illegal. These are spec-grounded negative cases the agent has not yet generated value diversity for. (3) Drop probe_request from heavy rotation: it has only 2 mandatory IEs (0 SSID, 1 Supported Rates) and 1 optional (50), the smallest attack surface in the corpus, and every mutation (including missing_mandatory at len=28 and reserved_ie at len=40) kept alive=1 across ~845 repetitions \u2014 further budget there is wasted. Keep a minimal probe_request smoke set but reallocate cycles to beacon (richer IE set incl. TIM/Country/RSN) and assoc_request (RSN + Extended Capabilities)."
}