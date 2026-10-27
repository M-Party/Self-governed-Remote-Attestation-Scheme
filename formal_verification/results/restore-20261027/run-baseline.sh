#!/bin/sh
# Run inside the restored image, with /work read-only and /results writable.
set -eu
cd /work
proverif -help > /results/proverif-version.txt 2>&1
opam list --installed --short > /results/opam-packages.txt
sha256sum sras-n2.pv sras-n3.pv sras-n3-ablation.pv > /results/model-sha256.txt
for model in sras-n2 sras-n3 sras-n3-ablation; do
    status=0
    /usr/bin/time -f 'elapsed_seconds=%e exit_status=%x' \
        -o "/results/time-parse-${model}.txt" \
        timeout 600 proverif -parse-only "${model}.pv" \
        > "/results/parse-${model}.txt" 2>&1 || status=$?
    printf '%s\n' "$status" > "/results/exit-parse-${model}.txt"
    if [ "$status" -ne 0 ]; then
        printf 'Parse failed: %s (exit %s)\n' "$model" "$status"
        exit "$status"
    fi
    status=0
    /usr/bin/time -f 'elapsed_seconds=%e exit_status=%x' \
        -o "/results/time-${model}.txt" \
        timeout 600 proverif "${model}.pv" \
        > "/results/results-${model}.txt" 2>&1 || status=$?
    printf '%s\n' "$status" > "/results/exit-${model}.txt"
    printf '%s: exit=%s\n' "$model" "$status"
    grep '^RESULT ' "/results/results-${model}.txt" || true
    if [ "$status" -ne 0 ]; then
        exit "$status"
    fi
done
mkdir -p /results/trace-ablation
status=0
/usr/bin/time -f 'elapsed_seconds=%e exit_status=%x' \
    -o /results/time-graph-sras-n3-ablation.txt \
    timeout 600 proverif -graph /results/trace-ablation sras-n3-ablation.pv \
    > /results/attack-trace-sras-n3-ablation.txt 2>&1 || status=$?
printf '%s\n' "$status" > /results/exit-graph-sras-n3-ablation.txt
printf 'Attack graph: exit=%s\n' "$status"
exit "$status"
