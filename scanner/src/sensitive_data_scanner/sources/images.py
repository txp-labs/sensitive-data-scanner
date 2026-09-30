"""Container images in ECR: files sampled from each repository's latest image's layers,
opt-in (`ECR_READ`), because a layer is large to download (#35).

With `DISCOVER` including `ecr`, the run lists the repositories
(`DescribeRepositories`, with each one's encryption) and, when reading is on,
takes each repository's most recently pushed image (`DescribeImages`), its
manifest (`BatchGetImage`; for a multi-platform index, the `linux/amd64`
image, else the first), and its top `ECR_MAX_LAYERS` layers, where an
application's own files are. Each layer is downloaded from the URL ECR signs
for it (`GetDownloadUrlForLayer`), at most `ECR_MAX_LAYER_BYTES`, and read as
a stream: gzip or plain tar (a zstd layer is counted, not read). Up to
`ECR_MAX_FILES_PER_LAYER` regular files per layer are read, outside the
operating system's own directories (`usr/`, `lib/`, `bin/`, ...), each to
`MAX_OBJECT_BYTES`, with the kinds S3 skips counted instead. A finding names
the repository, the layer (its digest, a hash) and the file's path. An image
is read once; a newer push starts a new pass. Nothing is pushed, tagged or
deleted; the role denies it.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import io
import json
import secrets
import tarfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from typing import IO, Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun, class_findings
from sensitive_data_core.coverage import Discovery, Store
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.item import classify_key, looks_binary, scan_item_text

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import drop_other_passes, merge

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("ecr",)

MANIFESTS = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
]
# The operating system's own files: an application's data is elsewhere.
SYSTEM_DIRS = frozenset(
    {"usr", "lib", "lib32", "lib64", "bin", "sbin", "boot", "dev", "proc", "sys"}
)

Fetch = Callable[[str, int], IO[bytes]]


def fetch(url: str, max_bytes: int) -> IO[bytes]:
    """GET a URL ECR signed for one layer (HTTPS to its storage), read as a stream."""
    if not url.startswith("https://"):
        raise ValueError("a layer URL must be HTTPS")
    request = urllib.request.Request(url, method="GET")  # noqa: S310 - HTTPS only, checked above
    response: IO[bytes] = urllib.request.urlopen(request, timeout=60)  # noqa: S310
    return response


class Capped(io.RawIOBase):
    """At most `limit` bytes of a stream; `cut` says whether there was more."""

    def __init__(self, raw: IO[bytes], limit: int) -> None:
        super().__init__()
        self.raw = raw
        self.left = limit
        self.read_bytes = 0
        self.cut = False

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self.left <= 0:
            self.cut = self.cut or bool(self.raw.read(1))
            return 0
        data = self.raw.read(min(len(b), self.left))
        n = len(data)
        b[:n] = data
        self.left -= n
        self.read_bytes += n
        return n


class EcrAdapter:
    kind = "ecr"

    def discover(self, ctx: Context, out: Discovery) -> None:
        ecr = ctx.clients.client("ecr")
        keys = classifier(ctx.clients)
        for page in ecr.get_paginator("describe_repositories").paginate():
            for r in page.get("repositories", []):
                store = Store(self.kind, str(r["repositoryName"]))
                out.stores.append(store)
                enc = r.get("encryptionConfiguration") or {}
                if str(enc.get("encryptionType") or "AES256").startswith("KMS"):
                    store.facts = keys.facts(key=enc.get("kmsKey"))
                else:
                    store.facts = keys.facts(aws_owned=True)
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        t = ecr.list_tags_for_resource(resourceArn=str(r.get("repositoryArn")))
                        store.tags = {
                            str(x["Key"]): str(x.get("Value", "")) for x in t.get("tags", [])
                        }
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status == "pending" and not ctx.config.ecr_read:
                    store.skip("read_not_configured")

    def source(self, ctx: Context, store: Store) -> EcrSource:
        c = ctx.config
        return EcrSource(
            ctx.clients.client("ecr"),
            ctx.clients.services.get("layer-fetch") or fetch,
            repository=store.name,
            region=ctx.region,
            max_layers=c.ecr_max_layers,
            max_layer_bytes=c.ecr_max_layer_bytes,
            max_files=c.ecr_max_files_per_layer,
            max_file_bytes=c.max_object_bytes,
        )


class EcrSource:
    """One repository's latest image: its top layers' files, sampled."""

    kind = "ecr"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        ecr: Any,
        fetcher: Fetch,
        *,
        repository: str,
        region: str,
        max_layers: int = 5,
        max_layer_bytes: int = 256 * 1024**2,
        max_files: int = 200,
        max_file_bytes: int = 20 * 1024**2,
    ) -> None:
        self.ecr = ecr
        self.fetch = fetcher
        self.repository = repository
        self.region = region
        self.max_layers = max_layers
        self.max_layer_bytes = max_layer_bytes
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.id = f"ecr:{hashlib.sha256(repository.encode()).hexdigest()[:16]}"
        self.target = repository

    def link(self) -> str:
        q = urllib.parse.quote(self.repository, safe="")
        return console_link(self.region, f"ecr/repositories/private/{q}?region={self.region}")

    def _latest(self) -> str | None:
        latest: dict[str, Any] | None = None
        for page in self.ecr.get_paginator("describe_images").paginate(
            repositoryName=self.repository
        ):
            for d in page.get("imageDetails", []):
                if latest is None or (
                    d.get("imagePushedAt") or _dt.datetime.min.replace(tzinfo=_dt.UTC)
                ) > (latest.get("imagePushedAt") or _dt.datetime.min.replace(tzinfo=_dt.UTC)):
                    latest = d
        return str(latest["imageDigest"]) if latest else None

    def _manifest(self, digest: str, depth: int = 0) -> dict[str, Any]:
        r = self.ecr.batch_get_image(
            repositoryName=self.repository,
            imageIds=[{"imageDigest": digest}],
            acceptedMediaTypes=MANIFESTS,
        )
        images = r.get("images") or []
        if not images:
            raise LookupError("ImageNotFound")
        manifest: dict[str, Any] = json.loads(str(images[0].get("imageManifest") or "{}"))
        if "manifests" in manifest and depth == 0:  # an index: one platform's image
            entries = manifest.get("manifests") or []
            chosen = next(
                (
                    m
                    for m in entries
                    if (m.get("platform") or {}).get("os") == "linux"
                    and (m.get("platform") or {}).get("architecture") == "amd64"
                ),
                entries[0] if entries else None,
            )
            if chosen is None:
                return {"layers": []}
            return self._manifest(str(chosen["digest"]), depth + 1)
        return manifest

    def run(
        self,
        cursor: dict[str, Any],
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        now: _dt.datetime,
    ) -> SourceRun:
        cov = Coverage(self.kind, self.target)
        seen_at, link = now.isoformat(), self.link()
        try:
            digest = self._latest()
            if digest is None:
                cov.pass_complete = True  # no image: nothing to read
                return SourceRun(cov, {}, None, {})
            same = cursor.get("image") == digest
            if same and cursor.get("done"):
                cov.pass_complete = True  # read in full; a newer push starts a new pass
                return SourceRun(cov, dict(cursor), None, {})
            pass_id = str(cursor.get("passId")) if same else secrets.token_hex(8)
            done_layers = list(cursor.get("layers") or []) if same else []
            layers = (self._manifest(digest).get("layers") or [])[-self.max_layers :]
            cov.listed = len(layers)
            todo = [x for x in reversed(layers) if str(x.get("digest")) not in done_layers]
            cov.eligible = len(todo)
            for layer in todo:
                if not budget.has(0):
                    break
                self._layer(layer, cov, budget, detector, store, seen_at, link, pass_id)
                done_layers.append(str(layer.get("digest")))
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, dict(cursor), None, {})
        if len(done_layers) >= len(layers):
            cov.pass_complete = True
            drop_other_passes(store, self.id, pass_id)
            return SourceRun(cov, {"image": digest, "done": True}, None, {})
        cov.backlog = True
        cursor_out = {"image": digest, "passId": pass_id, "layers": done_layers}
        return SourceRun(cov, cursor_out, None, {})

    def _members(self, stream: IO[bytes], media: str) -> Iterator[tuple[str, IO[bytes], int]]:
        if "zstd" in media:
            raise NotImplementedError("zstd")
        gz = "gzip" in media or "tar.gz" in media
        tar = (
            tarfile.open(fileobj=stream, mode="r|gz")  # noqa: SIM115 - closed by the with below
            if gz
            else tarfile.open(fileobj=stream, mode="r|")  # noqa: SIM115
        )
        with tar:  # read member by member from the stream, never extracted to disk
            for m in tar:
                if not m.isreg():
                    continue
                f = tar.extractfile(m)
                if f is not None:
                    yield m.name, f, int(m.size)

    def _layer(  # noqa: PLR0917 - one layer of the pass
        self,
        layer: dict[str, Any],
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        link: str,
        pass_id: str,
    ) -> None:
        digest = str(layer.get("digest"))
        media = str(layer.get("mediaType") or "")
        url = self.ecr.get_download_url_for_layer(
            repositoryName=self.repository, layerDigest=digest
        )["downloadUrl"]
        raw = Capped(self.fetch(str(url), self.max_layer_bytes), self.max_layer_bytes)
        stream = io.BufferedReader(raw, 1024 * 1024)
        files = 0
        try:
            for name, f, size in self._members(stream, media):
                path = name.lstrip("./")
                if path.split("/", 1)[0] in SYSTEM_DIRS:
                    continue
                read_it, _, kind = classify_key(path)
                if not read_it:
                    cov.skipped[kind or "binary"] = cov.skipped.get(kind or "binary", 0) + 1
                    continue
                if files >= self.max_files or not budget.has(size):
                    cov.sampled_out += 1
                    continue
                data = f.read(self.max_file_bytes)
                cov.partial += int(size > self.max_file_bytes)
                budget.take(len(data))
                if looks_binary(data):
                    cov.skipped["binary"] = cov.skipped.get("binary", 0) + 1
                    continue
                files += 1
                item = scan_item_text(path, data.decode("utf-8", "replace"), detector)
                cov.scanned += 1
                cov.bytes_scanned += len(data)
                cov.formats[item.format] = cov.formats.get(item.format, 0) + 1
                cov.test_values += item.test_values
                cov.suppressed += item.suppressed
                cov.redaction_markers += item.redaction_markers
                resource = store_field_resource(
                    service="ecr",
                    store=self.repository,
                    table=digest[:19],
                    field=path,
                    read_by="layer_sample",
                )
                for fnd in class_findings(
                    item.findings, resource, link, item.format, seen_at, facts=self.facts
                ):
                    merge(store, f"{self.id}\n{digest}\n{path}", fnd, pass_id)
        except NotImplementedError:
            cov.skipped["archive"] = cov.skipped.get("archive", 0) + 1  # a zstd layer
        except (tarfile.TarError, EOFError, OSError, gzip.BadGzipFile) as err:
            if raw.cut or raw.left <= 0:
                cov.partial += 1  # the byte cap fell inside the layer: what was read stands
            else:
                cov.unreadable += 1
                log_event("item.unreadable", source=self.target, error=error_name(err))
        if raw.cut:
            cov.partial += 1
