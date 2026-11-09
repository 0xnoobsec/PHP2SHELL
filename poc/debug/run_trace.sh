#!/usr/bin/env bash
# run_trace.sh <container> <port> <sid>
# Attaches gdb to the single prefork worker, fires the OOM request, records
# the worker pid before and after, and fails loudly if attachment didn't happen.
set -u
C=${1:?usage: run_trace.sh <container> [port] [sid]}
PORT=${2:-8095}
SID=${3:-dbgsess01}
HERE=$(cd "$(dirname "$0")" && pwd)

die() { echo "[!] $*" >&2; exit 1; }

CH=$(docker exec "$C" pgrep -u www-data apache2 2>/dev/null | head -1)
[ -n "${CH:-}" ] || die "no apache worker pid found in container $C"
echo "[*] worker pid before = $CH"

docker cp "$HERE/gdb.cmd" "$C:/tmp/gdb.cmd" >/dev/null || die "docker cp gdb.cmd failed"
docker exec "$C" sh -c 'rm -f /tmp/gdb.log; pkill -f "gdb -p" 2>/dev/null; true'

docker exec -d "$C" sh -c "gdb -p $CH -batch -x /tmp/gdb.cmd > /tmp/gdb.log 2>&1" \
  || die "could not start gdb in container (ptrace? SYS_PTRACE missing?)"

# wait for the breakpoint list, not just for a file to appear
attached=0
for _ in $(seq 1 30); do
  if docker exec "$C" sh -c 'grep -q "^Breakpoint 2" /tmp/gdb.log 2>/dev/null'; then
    attached=1; break
  fi
  sleep 0.5
done
[ "$attached" = "1" ] || { docker exec "$C" sh -c 'tail -5 /tmp/gdb.log' >&2; die "gdb did not attach / breakpoints not set"; }

python3 "$HERE/trigger_oom.py" --host 127.0.0.1 --port "$PORT" --sid "$SID"
sleep 4

CH2=$(docker exec "$C" pgrep -u www-data apache2 2>/dev/null | head -1)
echo "[*] worker pid after  = ${CH2:-<none>}"
if [ "${CH2:-}" != "$CH" ]; then
  echo "[!] worker pid changed during the run; the trace may span two request lifecycles" >&2
fi

echo "=== trace ==="
docker exec "$C" sh -c 'grep -vE "auto-load|safe-path|gdbinit|^For more|^line to|^\t|^$" /tmp/gdb.log'
docker exec "$C" sh -c 'pkill -f "gdb -p" 2>/dev/null; true'
