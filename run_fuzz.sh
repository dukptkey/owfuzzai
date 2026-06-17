#!/usr/bin/env bash
# End-to-end OTA fuzz runner for the WPA2 4-way (EAPOL) flow demonstrator.
# Bundles: monitor-mode setup -> concurrent on-air capture -> owfuzz run -> summary.
# Run on the fuzzer host (KPAX) after `cd owfuzz && make`. See FUZZER_IMPROVEMENTS.md.
#
#   ./run_fuzz.sh                          # pre-MIC (M2) parser fuzzing, run until Ctrl-C
#   DURATION=25 ./run_fuzz.sh              # bounded 25s run, then print a summary
#   PSK_FILE=/tmp/wifi_psk ./run_fuzz.sh   # post-auth coverage (-K); PSK read from file
#   SUDO_PW_FILE=/tmp/kpax_sudo DURATION=20 ./run_fuzz.sh   # non-interactive (warms sudo)
#
# Override any target/rig value via env (IFACE, CH, BSSID, SSID, SRCMAC, AUTH, ...).
set -euo pipefail

REPO=${REPO:-$(cd "$(dirname "$0")" && pwd)}
IFACE=${IFACE:-wlxcc641aefb56f}            # the test/monitor NIC (NOT the host's uplink)
CH=${CH:-100}                              # 5500 MHz
BSSID=${BSSID:-44:89:6d:eb:cf:8e}          # target AP
SSID=${SSID:-VIVOFIBRA-WIFI6-CF81}
SRCMAC=${SRCMAC:-de:ad:be:ef:00:01}        # our fuzzer STA (locally-administered)
AUTH=${AUTH:-WPA2_PSK_AES}
OWFUZZ=${OWFUZZ:-$REPO/owfuzz/src/owfuzz}
CORPUS=${CORPUS:-$REPO/corpusgen/samples/eapol_corpus.txt}
FLOW=${FLOW:-$REPO/corpusgen/samples/eapol.flow}
PSK_FILE=${PSK_FILE:-/tmp/wifi_psk}        # if readable -> run with -K (post-auth coverage)
DURATION=${DURATION:-}                     # seconds; empty = run until Ctrl-C
CAPTURE=${CAPTURE:-1}                       # 1 = capture an on-air pcap alongside the run
PCAP=${PCAP:-/tmp/owfuzz_run.pcap}
SUDO_PW_FILE=${SUDO_PW_FILE:-}             # if set, warm sudo non-interactively from this file

warm_sudo() {
	if [[ -n "$SUDO_PW_FILE" && -r "$SUDO_PW_FILE" ]]; then sudo -S -v < "$SUDO_PW_FILE" 2>/dev/null
	else sudo -v; fi
}

TCPD=""
cleanup() { [[ -n "$TCPD" ]] && sudo kill "$TCPD" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- step 2a: sanity check (every flow @send resolves to a corpus tag) ---
echo "[*] sanity: flow @send ids vs corpus tags"
fsends=$(grep -vE '^#|^$' "$FLOW" | awk -F'|' '{gsub(/ /,"",$3); print $3}' | grep -v '^-$' | sort -u)
for s in $fsends; do grep -q "@send=$s" "$CORPUS" || { echo "  MISSING @send=$s in corpus"; exit 1; }; done
echo "    ok: $fsends"

warm_sudo

# --- step 2b: monitor mode ---
echo "[*] monitor mode on $IFACE ch$CH"
sudo nmcli dev set "$IFACE" managed no 2>/dev/null || true
sudo ip link set "$IFACE" down
sudo iw dev "$IFACE" set type monitor
sudo ip link set "$IFACE" up
sudo iw dev "$IFACE" set channel "$CH"

K_ARG=()
if [[ -r "$PSK_FILE" ]]; then
	echo "[*] -K enabled (PSK from $PSK_FILE): completes the handshake into the post-auth surface"
	K_ARG=(-K "$(cat "$PSK_FILE")")
else
	echo "[*] no $PSK_FILE: pre-MIC (M2) parser fuzzing only"
fi

# --- step 4a: start the on-air capture ---
if [[ "$CAPTURE" == 1 ]]; then
	echo "[*] capturing on-air frames -> $PCAP"
	sudo tcpdump -i "$IFACE" -w "$PCAP" "wlan host $BSSID" >/dev/null 2>&1 &
	TCPD=$!
	sleep 1
fi

# --- step 3: run owfuzz ---
echo "[*] target $SSID ($BSSID) ch$CH ; WATCH THE ROUTER kernel log for faults:"
echo "    (on the router)  tail -f /persist/config/jean_kmsg | grep -iE 'oops|panic|BUG|call trace'"
RUN=("$OWFUZZ" -i "$IFACE" -m sta -c "$CH" -t "$BSSID" -b "$BSSID" -s "$SRCMAC" \
     -S "$SSID" -A "$AUTH" -T 1 -p "$CORPUS" -F "$FLOW" "${K_ARG[@]}")
if [[ -n "$DURATION" ]]; then
	echo "[*] running owfuzz for ${DURATION}s..."
	sudo timeout "$DURATION" "${RUN[@]}" >/tmp/owfuzz_run.log 2>&1 || true
else
	echo "[*] running owfuzz (Ctrl-C to stop)..."
	sudo "${RUN[@]}"
fi

# --- step 4b: stop capture + summarize ---
cleanup; TCPD=""; sleep 1
[[ "$CAPTURE" == 1 && -r "$PCAP" ]] || { echo "[*] done."; exit 0; }
echo
echo "===== summary ($PCAP) ====="
echo "-- frames we SENT (STA $SRCMAC) --"
sudo tcpdump -r "$PCAP" -nne "wlan src $SRCMAC" 2>/dev/null \
	| grep -oiE "Authentication|Assoc Request|EAPOL key" | sort | uniq -c
echo "-- AP responses to us (151=M3, 95=M1) --"
resp=$(sudo tcpdump -r "$PCAP" -nne "wlan src $BSSID and wlan dst $SRCMAC" 2>/dev/null || true)
printf '%s\n' "$resp" | grep -oiE "Authentication|Assoc Response|Deauth|len 151|len 95" | sort | uniq -c
m3=$(printf '%s\n' "$resp" | grep -c "len 151" || true)
echo
if [[ "${#K_ARG[@]}" -gt 0 && "$m3" -gt 0 ]]; then
	echo "[+] -K SUCCESS: AP sent $m3 M3 (len 151) -> it accepted our signed M2 (post-MIC parser reached)."
elif [[ "$m3" -gt 0 ]]; then
	echo "[i] AP sent M3 (len 151) even without -K? unexpected — inspect $PCAP."
else
	echo "[i] no M3: handshake stalled at M2 (expected without -K; with -K check the PSK)."
fi
echo "[*] crash check: inspect the router's /persist/config/jean_kmsg (oops/panic) for the run window."
