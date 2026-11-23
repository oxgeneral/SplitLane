set -euo pipefail
umask 077

engine_source=$1
engine_sha=$2
config_source=$3
config_sha=$4
lease=$5
token=$6
address=$7
system_v4=$8
system_v6=$9
shift 9
zone_script=$1
zone=$2
shift 2
interfaces=("$@")

[[ $token =~ ^[A-F0-9-]{36}$ ]]
state="/private/tmp/splitwebonmac-$token"
private="$state/private"
pid=
zone_journal=/var/db/local.splitwebonmac.time-zone-restore.json

restore_zone() {
    if [[ -e $zone_journal ]]; then
        /usr/bin/osascript -l JavaScript -e "$zone_script" -- restore
    fi
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

route_interface() {
    /sbin/route -n get "$@" 2>/dev/null | /usr/bin/awk '/^[[:space:]]*interface:/{print $2}'
}

network_snapshot() {
    for family in inet inet6; do
        /usr/sbin/netstat -rn -f "$family" | /usr/bin/awk '$1=="default"{print $2,$4}'
    done
    for interface in "${interfaces[@]}"; do
        /sbin/ifconfig "$interface" | /usr/bin/awk '/^[[:space:]]*(inet |inet6 |status:)/{print}'
    done
}

lease_live() {
    local stamp
    stamp="$(/usr/bin/stat -f %m "$lease" 2>/dev/null)" || return 1
    [[ $(($(/bin/date +%s) - stamp)) -lt 8 ]]
}

tun_interface() {
    /sbin/ifconfig | /usr/bin/awk -v address="$address" '
        /^[^[:space:]]/ {interface=$1; sub(/:$/, "", interface)}
        $1=="inet" && $2==address && interface ~ /^utun[0-9]+$/ {print interface}
    '
}

cleanup() {
    local zone_status=0
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || break
            /bin/sleep 1
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    restore_zone || zone_status=$?
    for path in "$state/ready" "$private/sing-box" "$private/config.json" "$private/engine.log"; do
        [[ ! -e $path ]] || /bin/rm "$path"
    done
    [[ ! -d $private ]] || /bin/rmdir "$private"
    /bin/rmdir "$state"
    return "$zone_status"
}

lease_live || exit 0
restore_zone
[[ $(route_interface -inet default) == "$system_v4" ]] ||
    fail "Системный маршрут изменился. Включи правила ещё раз."
[[ $(route_interface -inet6 default || true) == "$system_v6" ]] ||
    fail "Системный маршрут IPv6 изменился. Включи правила ещё раз."
[[ -z $(tun_interface) ]] || fail "Адрес сетевого интерфейса уже занят."
initial_network="$(network_snapshot)"

# This folder is created by root. Only the ready flag is readable by the app.
mkdir -m 755 "$state"
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
mkdir -m 700 "$private"
/bin/cp "$engine_source" "$private/sing-box"
/bin/cp "$config_source" "$private/config.json"
printf '%s  %s\n%s  %s\n' "$engine_sha" "$private/sing-box" "$config_sha" "$private/config.json" |
    /usr/bin/shasum -a 256 -c >/dev/null
"$private/sing-box" check -c "$private/config.json"
"$private/sing-box" run -c "$private/config.json" >> "$private/engine.log" 2>&1 &
pid=$!

tun=
for _ in {1..12}; do
    lease_live || exit 0
    kill -0 "$pid" 2>/dev/null || break
    tun="$(tun_interface)"
    if [[ -n "$tun" && $(route_interface 1.0.0.1 || true) == "$tun" &&
          $(route_interface 208.67.222.222 || true) == "$tun" &&
          $(route_interface -inet6 2606:4700:4700::1111 || true) == "$tun" ]]; then
        break
    fi
    tun=
    /bin/sleep 1
done
if [[ -z "$tun" ]]; then
    /usr/bin/tail -n 3 "$private/engine.log" >&2
    fail "macOS не направила тестовые адреса через новый интерфейс. Маршруты восстановлены."
fi

lease_live || exit 0
if [[ -n $zone ]]; then
    /usr/bin/osascript -l JavaScript -e "$zone_script" -- begin "$zone"
fi
printf '%s\n' "$tun" > "$state/ready"
chmod 644 "$state/ready"

while lease_live; do
    kill -0 "$pid" 2>/dev/null || fail "Движок остановился. Системные маршруты восстановлены."
    [[ $(network_snapshot) == "$initial_network" ]] ||
        fail "Подключение изменилось. Включи правила снова."
    if [[ $(/usr/bin/stat -f %z "$private/engine.log") -gt 1048576 ]]; then : > "$private/engine.log"; fi
    /bin/sleep 2
done
