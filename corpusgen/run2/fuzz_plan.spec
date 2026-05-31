{
  "focus_frames": [
    "beacon",
    "assoc_request"
  ],
  "focus_mutations": [
    "oversized_value",
    "len_overflow",
    "missing_mandatory",
    "dup_ie"
  ],
  "drop_frames": [
    "authentication"
  ],
  "rationale": "First fix the len_overflow generator so it emits a real declared-length-vs-actual mismatch (declared length > remaining buffer, and the 255-byte max) on a concrete IE \u2014 beacon SSID(0)/Supported Rates(1)/RSN(48) and assoc_request RSN(48)/Extended Capabilities(127) \u2014 since this boundary class was never delivered and is where parser overruns typically hide; pair it with oversized_value which is the only large-frame stimulus confirmed to reach the parser. Concentrate on beacon and assoc_request because they are IE-rich and accept many optional/conditional elements (DS, TIM, Country, RSN, Ext Rates, Ext Caps), giving real surface for dup_ie and missing_mandatory permutations; vary which mandatory element is dropped and which IE is duplicated rather than repeating one vector. Drop authentication: Open System has no IEs, so len_overflow/dup_ie/reserved_ie/missing_mandatory/oversized_value have no meaningful target there \u2014 instead its budget should later go to fuzzing the fixed fields (algorithm number incl. Shared Key=1/SAE=3, transaction sequence, status code) and Shared-Key Challenge Text (IE 16), which the current mutation set does not touch. Also cut the ~16x blind repetition of identical frames; spend that budget on new distinct vectors and on confirming any future crash with a tight replay loop."
}