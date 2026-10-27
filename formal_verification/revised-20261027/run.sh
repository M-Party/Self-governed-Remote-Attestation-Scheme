#!/bin/sh
# Usage: sh run.sh NEW_RUN_NAME [jobs.txt]
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
run_name=${1:-manual-$(date -u +%Y%m%d-%H%M%S)}
jobs_file=${2:-jobs.txt}
case "$run_name" in *[!a-zA-Z0-9_-]*|'') printf 'Invalid run name\n' >&2; exit 2;; esac
case "$jobs_file" in *[!a-zA-Z0-9_.-]*|'') printf 'Invalid job list name\n' >&2; exit 2;; esac
dest="$base/results/$run_name"
if [ -e "$dest" ]; then
    printf 'Refusing to overwrite existing results: %s\n' "$dest" >&2
    exit 2
fi
mkdir -p "$dest"
sudo -n docker version > "$dest/docker-version.txt"
sudo -n docker image inspect sras-proverif:latest > "$dest/image-inspect.json"
printf '%s\n' 'Source mount /work read-only; output mount /out writable; Docker networking disabled.' > "$dest/runner.txt"
sudo -n docker run --rm --network none \
  --mount "type=bind,source=$base,target=/work,readonly" \
  --mount "type=bind,source=$dest,target=/out" \
  sras-proverif:latest sh /work/run-in-container.sh "/work/$jobs_file"
