set -euo pipefail
umask 077
dir="$(/usr/bin/mktemp -d /private/tmp/splitweb-proxy.XXXXXX)"
cleanup() {
    [[ ! -e "$dir/overlay" ]] || /bin/rm "$dir/overlay"
    [[ ! -e "$dir/overlay.engine" ]] || /bin/rm "$dir/overlay.engine"
    /bin/rmdir "$dir"
}
trap cleanup EXIT
/bin/cp "$1" "$dir/overlay"
printf '%s  %s\n' "$2" "$dir/overlay" | /usr/bin/shasum -a 256 -c >/dev/null
shift 2
if [[ ${8:-} == protect ]]; then
    /bin/cp "$1" "$dir/overlay.engine"
    printf '%s  %s\n' "$2" "$dir/overlay.engine" | /usr/bin/shasum -a 256 -c >/dev/null
    shift 2
fi
"$dir/overlay" "$@"
