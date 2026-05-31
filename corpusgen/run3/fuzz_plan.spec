{
  "focus_frames": [
    "probe_request",
    "authentication",
    "assoc_request"
  ],
  "focus_mutations": [
    "oversized_value",
    "dup_ie",
    "missing_mandatory",
    "fixed_field_corrupt",
    "truncated"
  ],
  "drop_frames": [
    "beacon"
  ],
  "rationale": "Beacon coverage is saturated at ~450 replays with zero signal; AP-mode targets discard foreign beacons before deep parsing and continuing to fuzz beacons wastes replay budget with no realistic crash path. probe_request must be added immediately as it is completely absent yet exposes a distinct pre-association scanning-state parser. For authentication, a new fixed_field_corrupt mutation targeting the Algorithm Number (values 0xFFFF, 1, 3), Transaction Sequence (out-of-order values), and Status Code fields should be prioritized because state-machine mishandling at the fixed-field layer is a common embedded driver bug class unreachable via IE mutations alone. A truncated mutation (genuine frame truncation to fewer bytes than the fixed-field or IE minimum) should complement len_overflow, which currently leaves total frame length unchanged and therefore cannot trigger read-past-end conditions gated on frame size. oversized_value and dup_ie remain worth retaining on authentication and assoc_request where they showed no effect in isolation but have never been applied within a stateful sequence (valid auth exchange followed immediately by a mutated assoc_request), which is the scenario most likely to expose parser assumptions about prior state."
}