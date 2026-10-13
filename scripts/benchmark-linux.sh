#!/bin/sh
set -eu

tier=${1:-local}
output_dir=${2:-benchmark}

case "$tier" in
  *[!A-Za-z0-9_-]*|'')
    echo "invalid benchmark tier" >&2
    exit 2
    ;;
esac

test "$(uname -s)" = Linux || {
  echo "benchmark requires Linux" >&2
  exit 1
}
test -r /proc/meminfo || {
  echo "benchmark requires procfs" >&2
  exit 1
}

mkdir -p "$output_dir"
cpu_count=$(getconf _NPROCESSORS_ONLN)
memory_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
test "$cpu_count" -gt 0
test "$memory_kib" -gt 0
printf '%s %s %s\n' "$tier" "$cpu_count" "$memory_kib" > "$output_dir/profile-$tier.txt"
{
  uname -a
  if command -v lscpu >/dev/null 2>&1; then lscpu; fi
  if command -v free >/dev/null 2>&1; then free -b; fi
  go version
} > "$output_dir/hardware-$tier.txt"

benchmark_temp=$(mktemp -d /tmp/frs-benchmark.XXXXXX)
benchmark_binary="$benchmark_temp/build.test"
cleanup() {
  rm -f "$benchmark_binary"
  rmdir "$benchmark_temp" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

go test -c -o "$benchmark_binary" ./internal/build
"$benchmark_binary" -test.run '^$' -test.bench '^BenchmarkBuildRealFixture$' -test.benchtime=5x -test.benchmem > "$output_dir/results-$tier.txt" 2>&1 &
benchmark_pid=$!
peak_kib=0
while kill -0 "$benchmark_pid" 2>/dev/null; do
  current_kib=$(awk '/^VmHWM:/ {print $2}' "/proc/$benchmark_pid/status" 2>/dev/null || true)
  if [ -n "$current_kib" ] && [ "$current_kib" -gt "$peak_kib" ]; then
    peak_kib=$current_kib
  fi
  sleep 0.05
done
if ! wait "$benchmark_pid"; then
  cat "$output_dir/results-$tier.txt" >&2
  exit 1
fi
printf 'peak_rss_kib=%s\n' "$peak_kib" > "$output_dir/resources-$tier.txt"
cat "$output_dir/results-$tier.txt"

go test -run 'TestLoadDefaults|Test.*Concurrency|Test.*Backpressure' -count=1 ./internal/config ./internal/pipeline ./internal/source
