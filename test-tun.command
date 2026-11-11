#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

engine="$PWD/.build/engines/sing-box"
engine_sha=602bce530f540146e8e2feace24a81bdaf7873456203db0cda162811eb44f338
config="$PWD/.build/tun-probe.json"
if /usr/bin/pgrep -f '^/private/tmp/splitweb-test\.[^/]+/sing-box' >/dev/null; then
    printf 'Дождись окончания уже запущенной пробы.\n' >&2
    exit 1
fi
[[ "$(/usr/bin/shasum -a 256 "$engine" | /usr/bin/awk '{print $1}')" == "$engine_sha" ]]
[[ -x "$PWD/.build/tun-probe" ]]
"$PWD/.build/tun-probe" "$@" > "$config"
"$engine" check -c "$config"
config_sha="$(/usr/bin/shasum -a 256 "$config" | /usr/bin/awk '{print $1}')"

printf 'SplitWebOnMac · тест только для 1.0.0.1 на 2 минуты\nВведи пароль администратора в этом окне.\n'
/usr/bin/sudo /bin/bash -s -- "$engine" "$engine_sha" "$config" "$config_sha" <<'ROOT' 2>&1 | /usr/bin/tee "$PWD/.build/tun-probe.log"
set -euo pipefail
umask 077
dir="$(/usr/bin/mktemp -d /private/tmp/splitweb-test.XXXXXX)"
engine_pid=
timer_pid=
cleanup() {
    if [[ -n "$timer_pid" ]]; then kill -TERM "$timer_pid" 2>/dev/null || true; fi
    if [[ -n "$engine_pid" ]]; then
        kill -TERM "$engine_pid" 2>/dev/null || true
        wait "$engine_pid" 2>/dev/null || true
    fi
    [[ ! -e "$dir/sing-box" ]] || /bin/rm "$dir/sing-box"
    [[ ! -e "$dir/config.json" ]] || /bin/rm "$dir/config.json"
    /bin/rmdir "$dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
/bin/cp "$1" "$dir/sing-box"
/bin/cp "$3" "$dir/config.json"
printf '%s  %s\n%s  %s\n' "$2" "$dir/sing-box" "$4" "$dir/config.json" | /usr/bin/shasum -a 256 -c
"$dir/sing-box" run -c "$dir/config.json" &
engine_pid=$!
(
    /bin/sleep 120
    kill -TERM "$engine_pid" 2>/dev/null || true
) &
timer_pid=$!
wait "$engine_pid"
ROOT
