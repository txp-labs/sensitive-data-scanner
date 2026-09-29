#!/usr/bin/env bash
# Build the Lambda zip deployment package (x86_64, Python 3.12, glibc 2.28+:
# the python3.12 runtime is Amazon Linux 2023) from the lock
# file: locked, hash-checked dependencies for manylinux, plus the scanner.
#
#   scripts/build-lambda-zip.sh <version> <out-dir>
#
# The handler is sensitive_data_scanner.handler.handler (runtime python3.12).
set -euo pipefail
version="${1:?version}"
out="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$root/scanner"
uv export --frozen --no-dev --no-emit-project -o "$work/requirements.txt"
uv pip install \
  --python 3.12 \
  --target "$work/package" \
  --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 \
  --only-binary :all: \
  --require-hashes \
  -r "$work/requirements.txt"
uv build --wheel --out-dir "$work/dist"
uv pip install --python 3.12 --target "$work/package" --no-deps "$work"/dist/*.whl
"$root/scripts/slim-site-packages.sh" "$work/package"
mkdir -p "$work/package/licenses"
cp "$root/LICENSE" "$root/NOTICE" "$work/package/licenses/"
cp -r "$root/third_party" "$work/package/licenses/"

zip_path="$out/sensitive-data-scanner-${version}-lambda-python3.12-x86_64.zip"
# Stable file order and timestamps, so the zip is reproducible from the tag.
(cd "$work/package" && find . -type f -print0 | LC_ALL=C sort -z \
  | xargs -0 touch -h -d '2026-01-01T00:00:00Z' \
  && find . -type f | LC_ALL=C sort | zip -X -q -@ "$zip_path")
du -sh "$work/package" | awk '{print "unzipped: " $1}'
du -sh "$zip_path" | awk '{print "zipped:   " $1}'
