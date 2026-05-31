{
  "focus_frames": [
    "beacon",
    "assoc_request",
    "authentication"
  ],
  "focus_mutations": [
    "ie_truncated_length",
    "ie_length_overflow",
    "rsn_suite_count_mismatch",
    "beacon_tim_corrupt",
    "beacon_ds_channel_oor",
    "beacon_country_truncated",
    "challenge_text_in_open_auth",
    "oversized_value"
  ],
  "drop_frames": [
    "probe_request"
  ],
  "rationale": "beacon must be added immediately \u2014 it is the largest unexercised family and the AP's IE parser for management frames is most consistently reachable via beacon injection regardless of association state. Recommended beacon mutations: ie_truncated_length (set SSID IE length = 0xFF so the IE walk reads past frame end), ie_length_overflow (set RSN IE length = 0xFF), beacon_tim_corrupt (DTIM Period = 0, Bitmap Control = 0xFF, partial bitmap length mismatch), beacon_ds_channel_oor (DS Parameter Set channel = 0x00 or 0xFF), beacon_country_truncated (Country IE length = 1, missing regulatory triplets). assoc_request should stay but shift to rsn_suite_count_mismatch (Pairwise Count claims 3 suites, only 1 suite present in IE body) and ie_truncated_length applied to the RSN IE specifically; these target the counter-driven loops that are distinct from the bulk-length checks that oversized_value already exercised. authentication should include challenge_text_in_open_auth (append IE 16 to an Open System algo=0 frame, which is undefined and may confuse length-driven parsers). probe_request is dropped: an AP in infrastructure mode does not crash from malformed Probe Requests in practice \u2014 1556 frames across all mutations confirmed survival \u2014 and the probe path is structurally simpler than beacon or association paths. Eliminating probe_request frees the full frame budget for beacon (which has zero prior coverage) and deeper assoc_request mutations. The corpus generator must also ensure each unique frame appears only once per campaign run to stop wasting budget on repetition of already-surviving seeds."
}