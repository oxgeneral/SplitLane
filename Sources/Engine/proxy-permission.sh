permission_rule() {
    printf '#%s ALL=(root) NOPASSWD: sha256:%s /Library/PrivilegedHelperTools/local.splitlane.proxy-overlay.%s ^--authorized [0-9A-F-]+ /[a-zA-Z0-9_/.-]+/lease %s [0-9]+ [0-9]+( protect %s)?( zone [a-zA-Z0-9_+-]+(/[a-zA-Z0-9_+-]+)*)?$\n' \
        "$1" "$2" "$1" "$3" "$1"
}

if [[ "${BASH_SOURCE[0]:-$0}" != "$0" ]]; then return; fi

set -euo pipefail
umask 077
action=$1
uid=$2
[[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 1
helper="/Library/PrivilegedHelperTools/local.splitlane.proxy-overlay.$uid"
rule="/private/etc/sudoers.d/local-splitlane-$uid"

if [[ "$action" == remove ]]; then
    /bin/rm -f "$rule" "$helper" "$helper.engine"
    exit
fi
[[ "$action" == install && $# -eq 7 && "$4" =~ ^[0-9a-f]{64}$ && "$5" =~ ^[0-9]{1,5}$ && "$7" =~ ^[0-9a-f]{64}$ ]] || exit 1

stage="$(/usr/bin/mktemp -d /private/tmp/splitlane-permission.XXXXXX)"
trap '/bin/rm -rf "$stage"' EXIT
/bin/cp "$3" "$stage/overlay"
/bin/cp "$6" "$stage/engine"
printf '%s  %s\n%s  %s\n' "$4" "$stage/overlay" "$7" "$stage/engine" | /usr/bin/shasum -a 256 -c >/dev/null
permission_rule "$uid" "$4" "$5" > "$stage/sudoers"
/usr/sbin/visudo -cf "$stage/sudoers" >/dev/null
for directory in "${helper%/*}" "${rule%/*}"; do
    if [[ ! -d "$directory" ]]; then
        /usr/bin/install -d -o root -g wheel -m 0755 "$directory"
    fi
done
/usr/bin/install -o root -g wheel -m 0755 "$stage/overlay" "$helper"
/usr/bin/install -o root -g wheel -m 0755 "$stage/engine" "$helper.engine"
/usr/bin/install -o root -g wheel -m 0440 "$stage/sudoers" "$rule"
user="$(/usr/bin/id -un "$uid")"
permission_check() {
    /usr/bin/sudo -n -u "$user" -- /usr/bin/sudo -n -l -- "$helper" --authorized \
        00000000-0000-0000-0000-000000000000 /var/folders/test/lease "$port" 2 3 "$@" >/dev/null 2>&1
}
port=$5
if ! permission_check || ! permission_check zone America/New_York || \
    ! permission_check protect "$uid" zone America/New_York; then
    /bin/rm -f "$rule" "$helper" "$helper.engine"
    printf '%s\n' 'macOS не приняла разрешение SplitLane.' >&2
    exit 1
fi
