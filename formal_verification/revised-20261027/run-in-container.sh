#!/bin/sh
# /work is the read-only package; /out is a fresh writable results directory.
set -eu
cd /work
seconds=${SRAS_TIMEOUT_SECONDS:-600}
graphs=${SRAS_GRAPHS:-1}
case "$seconds" in *[!0-9]*|'') printf 'Invalid timeout\n' >&2; exit 2;; esac
case "$graphs" in 0|1) ;; *) printf 'Invalid graphs flag\n' >&2; exit 2;; esac
proverif -help > /out/proverif-version.txt 2>&1
dot -V > /out/graphviz-version.txt 2>&1
uname -a > /out/container-kernel.txt
opam list --installed > /out/opam-packages.txt
overall=0
while IFS='|' read -r name source category participants; do
    [ -n "$name" ] || continue
    dest="/out/$name"
    mkdir -p "$dest/graphs"
    cp "$source" "$dest/model.pv"
    sha256sum "$source" > "$dest/model.sha256"
    printf '%s\n' "timeout $seconds proverif -parse-only $dest/model.pv" > "$dest/parse-command.txt"
    status=0
    /usr/bin/time -f 'elapsed_seconds=%e user_seconds=%U system_seconds=%S max_rss_kb=%M exit_status=%x' \
      -o "$dest/parse-time.txt" timeout "$seconds" proverif -parse-only "$dest/model.pv" \
      > "$dest/parse.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$dest/parse-exit.txt"
    if [ "$status" -ne 0 ]; then
        printf 'PARSE FAILED %s exit=%s\n' "$name" "$status"
        overall=1
        continue
    fi
    if [ "$graphs" -eq 1 ]; then
        set -- -graph "$dest/graphs" "$dest/model.pv"
    else
        set -- "$dest/model.pv"
    fi
    printf '%s\n' "timeout $seconds proverif $*" > "$dest/command.txt"
    status=0
    /usr/bin/time -f 'elapsed_seconds=%e user_seconds=%U system_seconds=%S max_rss_kb=%M exit_status=%x' \
      -o "$dest/time.txt" timeout "$seconds" proverif "$@" \
      > "$dest/output.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$dest/exit.txt"
    printf 'DONE %s exit=%s ' "$name" "$status"
    cat "$dest/time.txt"
    grep '^RESULT ' "$dest/output.log" || true
    [ "$status" -eq 0 ] || overall=1
done < "${1:-/work/jobs.txt}"
exit "$overall"
