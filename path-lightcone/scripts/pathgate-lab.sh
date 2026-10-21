#!/bin/sh
# PATHGATE-1 lab (path-lightcone/PATHGATE-1-PRECOMMIT.md). Runs ONLY inside a private user + network
# namespace: invoke as   unshare -Urn sh scripts/pathgate-lab.sh BIN EVIDENCE OUT
# Nothing here touches the host's firewall, routes or interfaces.
set -eu
BIN=$1 EV=$2 OUT=$3
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || { echo "refusing: not in a private netns"; exit 2; }
export PATHGATE_LAB=1
mkdir -p "$OUT"
ip link set lo up
ip link add pg0 type veth peer name pg1
ip link set pg0 mtu 9000 up
ip link set pg1 mtu 9000 up
M0=$(ip -br link show pg0 | awk "{print \$3}")
M1=$(ip -br link show pg1 | awk "{print \$3}")
nft -f - <<NFT
table inet pathgate {
  chain gate { type filter hook prerouting priority -300; policy accept; iifname "pg1" queue to 11; }
  chain observe { type filter hook prerouting priority -200; policy accept; iifname "pg1" queue flags bypass to 12; }
}
NFT
nft list ruleset > "$OUT/ruleset.txt"
sleep 1 # let the veth's own IPv6 autoconfiguration chatter pass

ready() { for _ in $(seq 100); do grep -q READY "$1" 2>/dev/null && return 0; sleep 0.05; done; echo "no READY in $1"; exit 1; }

phase() { # name, gate seconds (0 = no gate), classes
  NAME=$1 GS=$2 CL=$3
  "$BIN" observe 12 30 > "$OUT/$NAME-observed.txt" & OB=$!
  ready "$OUT/$NAME-observed.txt"
  GP=""
  if [ "$GS" != 0 ]; then
    "$BIN" gate "$EV" 11 "$GS" > "$OUT/$NAME-gate.txt" & GP=$!
    ready "$OUT/$NAME-gate.txt"
  fi
  if [ "$NAME" = gate-exit ]; then wait "$GP"; GP=""; fi
  "$BIN" inject "$EV" pg0 "$M1" "$M0" "$CL" "$OUT/$NAME-manifest.txt" > "$OUT/$NAME-inject.txt"
  sleep 0.5
  [ -n "$GP" ] && kill "$GP" 2>/dev/null || true
  kill "$OB" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "== $NAME"
  if [ -f "$OUT/$NAME-gate.txt" ]; then "$BIN" report "$OUT/$NAME-manifest.txt" "$OUT/$NAME-observed.txt" "$OUT/$NAME-gate.txt"; else "$BIN" report "$OUT/$NAME-manifest.txt" "$OUT/$NAME-observed.txt"; fi
}

phase no-gate 0 pos
phase gate 25 all
phase gate-exit 2 pos
nft delete chain inet pathgate gate
phase baseline 0 pos
nft list ruleset > "$OUT/ruleset-after.txt"
