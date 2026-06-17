#!/usr/bin/env bash
# End-to-end OTA fuzz runner for the WPA2 4-way (EAPOL) flow demonstrator.
# Run on the fuzzer host after `cd owfuzz && make`. See FUZZER_IMPROVEMENTS.md and
# corpusgen/samples/eapol_4way_recon.md for the design.
#
#   ./run_fuzz.sh                      # pre-MIC (M2) parser fuzzing
#   PSK_FILE=/tmp/wifi_psk ./run_fuzz.sh   # post-auth coverage (-K), PSK read from file
#
# Override any target/rig value via env (IFACE, CH, BSSID, SSID, SRCMAC, ...).
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

echo "[*] sanity: every flow @send resolves to a corpus tag"
fsends=$(grep -vE '^#|^$' "$FLOW" | awk -F'|' '{gsub(/ /,"",$3); print $3}' | grep -v '^-$' | sort -u)
for s in $fsends; do grep -q "@send=$s" "$CORPUS" || { echo "  MISSING @send=$s in corpus"; exit 1; }; done
echo "    ok: $fsends"

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

echo "[*] target $SSID ($BSSID) ch$CH ; watch the router's kernel log for faults"
echo "[*] running owfuzz (Ctrl-C to stop)"
exec sudo "$OWFUZZ" -i "$IFACE" -m sta -c "$CH" \
	-t "$BSSID" -b "$BSSID" -s "$SRCMAC" -S "$SSID" -A "$AUTH" -T 1 \
	-p "$CORPUS" -F "$FLOW" "${K_ARG[@]}"
