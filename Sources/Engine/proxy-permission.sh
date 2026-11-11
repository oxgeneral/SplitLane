set -euo pipefail
umask 077
action=$1
uid=$2
[[ "$uid" =~ ^[1-9][0-9]*$ ]]
helper="/Library/PrivilegedHelperTools/local.splitwebonmac.proxy-overlay.$uid"
rule="/private/etc/sudoers.d/local-splitwebonmac-$uid"

if [[ "$action" == remove ]]; then
    /bin/rm -f "$rule" "$helper"
    exit
fi
[[ "$action" == install && "$4" =~ ^[0-9a-f]{64}$ && "$5" =~ ^[0-9]{1,5}$ ]]

stage="$(/usr/bin/mktemp -d /private/tmp/splitweb-permission.XXXXXX)"
trap '/bin/rm -rf "$stage"' EXIT
/bin/cp "$3" "$stage/overlay"
printf '%s  %s\n' "$4" "$stage/overlay" | /usr/bin/shasum -a 256 -c >/dev/null
printf '#%s ALL=(root) NOPASSWD: sha256:%s %s ^--authorized [0-9A-F-]+ /[a-zA-Z0-9_/.-]+/lease %s [0-9]+$\n' \
    "$uid" "$4" "$helper" "$5" > "$stage/sudoers"
/usr/sbin/visudo -cf "$stage/sudoers" >/dev/null
/usr/bin/install -o root -g wheel -m 0755 "$stage/overlay" "$helper"
/usr/bin/install -o root -g wheel -m 0440 "$stage/sudoers" "$rule"
user="$(/usr/bin/id -un "$uid")"
if ! /usr/bin/sudo -n -u "$user" -- /usr/bin/sudo -n -l -- "$helper" --authorized \
    00000000-0000-0000-0000-000000000000 /var/folders/test/lease "$5" 2 >/dev/null 2>&1; then
    /bin/rm -f "$rule" "$helper"
    printf '%s\n' 'macOS не приняла разрешение SplitWebOnMac.' >&2
    exit 1
fi
