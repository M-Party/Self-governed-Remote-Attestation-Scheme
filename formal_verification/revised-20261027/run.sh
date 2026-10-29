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
cp "$base/$jobs_file" "$dest/jobs.txt"
mkdir "$dest/source-dependencies"
cp "$base/generate_models.py" "$dest/source-dependencies/"
cp "$base/models/algebra.pvl" "$dest/source-dependencies/"
for helper in stage123_regression.py stage123_complete.py stage123_supplement.py; do
    if [ -f "$base/$helper" ]; then
        cp "$base/$helper" "$dest/source-dependencies/"
    fi
done
printf 'timeout_seconds=%s\nmemory_limit=%s\n' "${SRAS_TIMEOUT_SECONDS:-600}" "${SRAS_MEMORY:-4g}" > "$dest/limits.txt"
printf 'graphs=%s\n' "${SRAS_GRAPHS:-1}" >> "$dest/limits.txt"
sudo -n docker version > "$dest/docker-version.txt"
sudo -n docker image inspect sras-proverif:latest > "$dest/image-inspect.json"
printf '%s\n' 'Source mount /work read-only; output mount /out writable; Docker networking disabled.' > "$dest/runner.txt"
sudo -n docker run --rm --network none \
  --memory "${SRAS_MEMORY:-4g}" --memory-swap "${SRAS_MEMORY:-4g}" \
  -e "SRAS_TIMEOUT_SECONDS=${SRAS_TIMEOUT_SECONDS:-600}" \
  -e "SRAS_GRAPHS=${SRAS_GRAPHS:-1}" \
  --mount "type=bind,source=$base,target=/work,readonly" \
  --mount "type=bind,source=$dest,target=/out" \
  sras-proverif:latest sh /work/run-in-container.sh "/work/$jobs_file"
