#!/bin/sh
# PATHGATE-2 lab (path-lightcone/PATHGATE-1-PRECOMMIT.md, PATHGATE-2). Every role, both directions.
# Runs ONLY inside a private user + network namespace:
#   unshare -Urn sh scripts/pathgate2-lab.sh BIN EVIDENCE OUT
set -eu
BIN=$1 EV=$2 OUT=$3
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || { echo "refusing: not in a private netns"; exit 2; }
export PATHGATE_LAB=1
mkdir -p "$OUT"
ip link set lo up
ip link add pg0 type veth peer name pg1
ip link set pg0 mtu 9000 up
ip link set pg1 mtu 9000 up
ip route add default dev pg0
ip -6 route add default dev pg0
M0=$(ip -br link show pg0 | awk "{print \$3}")
M1=$(ip -br link show pg1 | awk "{print \$3}")
sleep 1

ready() { for _ in $(seq 100); do grep -q READY "$1" 2>/dev/null && return 0; sleep 0.05; done; echo "no READY in $1"; exit 1; }

table() { # in|out
  if [ "$1" = in ]; then
    nft -f - <<NFT
table inet pathgate {
  chain gate { type filter hook prerouting priority -300; policy accept; iifname "pg1" queue to 11; }
  chain observe { type filter hook prerouting priority -200; policy accept; iifname "pg1" queue flags bypass to 12; }
}
NFT
  else
    nft -f - <<NFT
table inet pathgate {
  chain gate { type filter hook output priority -300; policy accept; oifname "pg0" queue to 11; }
  chain observe { type filter hook postrouting priority -200; policy accept; oifname "pg0" queue flags bypass to 12; }
}
NFT
  fi
}

phase() { # role dir name gate-seconds classes
  R=$1 D=$2 NAME=$3 GS=$4 CL=$5 P="$OUT/$1-$2-$3"
  "$BIN" observe 12 30 > "$P-observed.txt" & OB=$!
  ready "$P-observed.txt"
  GP=""
  if [ "$GS" != 0 ]; then
    "$BIN" gate "$EV" "$R" 11 "$GS" > "$P-gate.txt" & GP=$!
    ready "$P-gate.txt"
  fi
  if [ "$NAME" = gate-exit ]; then wait "$GP"; GP=""; fi
  IF=pg0
  "$BIN" inject "$EV" "$R" "$D" "$IF" "$M1" "$M0" "$CL" "$P-manifest.txt" > "$P-inject.txt"
  sleep 0.5
  [ -n "$GP" ] && kill "$GP" 2>/dev/null || true
  kill "$OB" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "== $R $D $NAME ($(tail -1 "$P-inject.txt"))"
  if [ -f "$P-gate.txt" ]; then "$BIN" report "$P-manifest.txt" "$P-observed.txt" "$P-gate.txt"; else "$BIN" report "$P-manifest.txt" "$P-observed.txt"; fi
}

for R in hub source receiver; do
  for D in in out; do
    table "$D"
    nft list ruleset > "$OUT/$R-$D-ruleset.txt"
    phase "$R" "$D" no-gate 0 pos
    phase "$R" "$D" gate 25 all
    phase "$R" "$D" gate-exit 2 pos
    nft delete chain inet pathgate gate
    phase "$R" "$D" baseline 0 pos
    nft delete table inet pathgate
  done
done
nft list ruleset > "$OUT/ruleset-after.txt"
