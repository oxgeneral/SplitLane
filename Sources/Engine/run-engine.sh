set -euo pipefail
engine=$1
config=$2
lease=$3
"$engine" run -c "$config" &
pid=$!
cleanup() {
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM
while kill -0 "$pid" 2>/dev/null; do
    stamp="$(/usr/bin/stat -f %m "$lease" 2>/dev/null || echo 0)"
    [[ $(($(/bin/date +%s) - stamp)) -lt 8 ]] || exit 0
    /bin/sleep 1
done
wait "$pid"
