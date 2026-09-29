#!/usr/bin/env bash
# Build the Lambda zip deployment package (x86_64, Python 3.12, glibc 2.28+:
# the python3.12 runtime is Amazon Linux 2023) from the lock
# file: locked, hash-checked dependencies for manylinux, plus the scanner and
# its cloud-neutral core (scanner/core).
#
#   scripts/build-lambda-zip.sh <version> <out-dir>
#
# The handler is sensitive_data_scanner.handler.handler (runtime python3.12).
#
# The zip carries no pyarrow (the `columnar` dependency group): with it the
# package would pass Lambda's 250 MB unzipped limit. The zip therefore reads
# every text format, gzip and Avro (null, deflate, bzip2, xz), and counts
# Parquet, ORC, zstd and snappy/zstandard Avro as skipped `columnar`. The
# container image reads them all.
set -euo pipefail
version="${1:?version}"
out="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$root/scanner"
# Third-party dependencies only: the core (a workspace member) is built as a
# wheel below with the scanner, not installed from the export as an editable path.
uv export --frozen --no-default-groups --no-emit-workspace -o "$work/requirements.txt"
uv pip install \
  --python 3.12 \
  --target "$work/package" \
  --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 \
  --only-binary :all: \
  --require-hashes \
  -r "$work/requirements.txt"
uv build --wheel --package sensitive-data-scanner-core --out-dir "$work/dist"
uv build --wheel --package sensitive-data-scanner --out-dir "$work/dist"
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
