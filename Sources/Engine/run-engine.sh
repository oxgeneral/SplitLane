set -euo pipefail
engine=$1
config=$2
lease=$3
app_pid=$4
"$engine" run --disable-color -c "$config" &
pid=$!
sleep_pid=
grace_pid=
cleanup() {
    if [[ -n "$sleep_pid" ]]; then kill -TERM "$sleep_pid" 2>/dev/null || true; fi
    if [[ -n "$grace_pid" ]]; then kill -TERM "$grace_pid" 2>/dev/null || true; fi
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
while kill -0 "$pid" 2>/dev/null && kill -0 "$app_pid" 2>/dev/null && [[ -f "$lease" ]]; do
    /bin/sleep 1 &
    sleep_pid=$!
    wait "$sleep_pid" 2>/dev/null || true
    sleep_pid=
done
if kill -0 "$pid" 2>/dev/null; then
    # Keep serving until the privileged helper restores macOS and the app stops us.
    # The delay also gives the helper time to restore settings after the app is killed.
    /bin/sleep 12 &
    grace_pid=$!
    wait "$grace_pid"
    exit 0
fi
wait "$pid"
