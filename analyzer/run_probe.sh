#!/bin/bash
# Sandtrap probe runner (INSIDE the sandbox): lure services + strace around one driver run.
# usage: run_probe.sh OUT_DIR MODE(observe|lure) TIMEOUT_S OFFSET_DAYS PYTHON DRIVER REPLY_FILE TOKENS_FILE [IGNORE_PREFIX]
OUT=$1; MODE=$2; TMO=$3; OFFSET=${4:-0}; PY=$5; DRIVER=$6; REPLY=$7; TOKENS=$8; IGN=${9:-/root/work/venv}
mkdir -p "$OUT" /root/work
: > "$OUT/sink.jsonl"; rm -f "$OUT/sink.ready"
cp /etc/resolv.conf /tmp/resolv.conf.bak 2>/dev/null

python3 /opt/sandtrap/sink.py --mode "$MODE" --log "$OUT/sink.jsonl" --tokens "$TOKENS" --reply-file "$REPLY" --ready "$OUT/sink.ready" >"$OUT/sink.out" 2>&1 &
SINK=$!
for i in $(seq 1 50); do [ -f "$OUT/sink.ready" ] && break; sleep 0.1; done
echo "nameserver 127.0.0.1" > /etc/resolv.conf

REDIRECT=0
if [ "$MODE" = "lure" ]; then
  # catch-all: any outbound TCP (raw IPs, odd ports) lands in the sink instead of leaving the VM
  iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 ! -d 169.254.169.254 -j REDIRECT --to-ports 8080 >>"$OUT/sink.out" 2>&1 && REDIRECT=1
fi
if [ "$OFFSET" -gt 0 ]; then date -s "+${OFFSET} days" >/dev/null 2>&1; fi

cd /root/work
START=$(date +%s.%N)
strace -f -qq -ttt -s 256 \
  -e trace=execve,connect,openat,open,unlink,unlinkat,rename,renameat,chmod,fchmodat,nanosleep,clock_nanosleep \
  -o "$OUT/trace.log" timeout -k 2 "$TMO" "$PY" "$DRIVER" >"$OUT/stdout" 2>"$OUT/stderr"
echo $? > "$OUT/exit"
END=$(date +%s.%N)

if [ "$OFFSET" -gt 0 ]; then date -s "-${OFFSET} days" >/dev/null 2>&1; fi
[ "$REDIRECT" = "1" ] && iptables -t nat -D OUTPUT -p tcp ! -d 127.0.0.0/8 ! -d 169.254.169.254 -j REDIRECT --to-ports 8080 2>/dev/null
cp /tmp/resolv.conf.bak /etc/resolv.conf 2>/dev/null
kill "$SINK" 2>/dev/null; wait "$SINK" 2>/dev/null

DUR=$(python3 -c "print(round($END-$START,3))")
python3 /opt/sandtrap/parse_trace.py --trace "$OUT/trace.log" --sink "$OUT/sink.jsonl" --tokens "$TOKENS" \
  --exit "$OUT/exit" --duration "$DUR" --ignore-prefix "$IGN" --out "$OUT/events.json"
echo "probe-done mode=$MODE redirect=$REDIRECT offset=$OFFSET dur=$DUR exit=$(cat $OUT/exit)"
