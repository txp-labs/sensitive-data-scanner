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
`MAX_OBJECT_BYTES`, by the core's reader (`scan/objects.py`), as S3 reads
them: each member's first bytes say what it is, so audio, video, images and
binaries (whatever their names) are counted, not read, and do not count
toward the files cap; Word, Excel and PowerPoint files, PDFs and archives (a
`.jar`, a `.whl`, a `.tar.gz`) are read as their text and by entry, from the
member's first `MAX_OBJECT_BYTES` (a larger zip's directory is past the cap,
so it is counted). A finding names the repository, the layer (its digest, a
hash) and the file's path (and, in an archive, the entry's: `archivePath`). An image
is read once; a newer push starts a new pass. Nothing is pushed, tagged or
deleted; the role denies it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
import urllib.parse
import urllib.request
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage
from sensitive_data_core.index import Indexes, ObjectPass
from sensitive_data_core.safety import error_name, log_event

from ..discovery import decide, needs_tags
from ..resources import console_link
from . import images_read as _read_path
from .base import Context
from .encryption import classifier
from .exports import drop_other_passes
from .images_read import Fetch, fetch

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("ecr",)

MANIFESTS = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
]


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
            max_inflated_bytes=c.max_inflated_bytes,
        )


class EcrSource:
    """One repository's latest image: its top layers' files, sampled.

    With the object index (#67), a layer is indexed by its digest (its content's hash), with
    what its files were read with: a newer image reads only the layers it has not read (or
    whose recorded components are stale), and an image already read in full is read again
    only for the layers a changed component could read differently."""

    kind = "ecr"
    facts: dict[str, Any] | None = None
    # A change to how this kind is listed (`listing:<kind>`) drops these cursor keys: the next
    # pass lists the store again from the start and reads only what changed (#67).
    relist_keys: tuple[str, ...] = ("image", "done", "passId", "layers", "rescan")
    indexes: Indexes | None = None  # the run's object indexes (#67), set by the runner

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
        max_inflated_bytes: int = 100 * 1024**2,
    ) -> None:
        self.ecr = ecr
        self.fetch = fetcher
        self.repository = repository
        self.region = region
        self.max_layers = max_layers
        self.max_layer_bytes = max_layer_bytes
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_inflated_bytes = max_inflated_bytes
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
        op = ObjectPass(self.indexes, self.id, self.kind, budget=budget)
        rescan = bool(cursor.get("rescan"))
        indexed = bool(cursor.get("indexed"))
        try:
            digest = self._latest()
            if digest is None:
                cov.pass_complete = True  # no image: nothing to read
                return SourceRun(cov, {}, None, {})
            same = cursor.get("image") == digest
            if same and cursor.get("done"):
                if not op.needs_enumeration(indexed=indexed):
                    cov.pass_complete = True  # read in full; a newer push starts a new pass
                    op.settle(cov)
                    return SourceRun(cov, dict(cursor), None, {})
                same, rescan = False, True  # the same image, for its stale layers (#67)
            elif not same:
                rescan = False
            pass_id = str(cursor.get("passId")) if same else secrets.token_hex(8)
            done_layers = list(cursor.get("layers") or []) if same else []
            layers = (self._manifest(digest).get("layers") or [])[-self.max_layers :]
            cov.listed = len(layers)
            todo = [x for x in reversed(layers) if str(x.get("digest")) not in done_layers]
            cov.eligible = len(todo)
            for layer in todo:
                if not budget.has(0):
                    break
                layer_digest = str(layer.get("digest"))
                decision = op.decide(layer_digest, changed=not rescan, marker=layer_digest)
                if not (decision.read or decision.rescan):
                    # A layer this scanner read, with what it would read it with now.
                    op.carry(store, f"{self.id}\n{layer_digest}\n", pass_id)
                    done_layers.append(layer_digest)
                    continue
                if decision.why is not None and not op.rescans.admit():
                    op.rescans.miss(decision.why)
                    break
                self._layer(
                    layer, cov, budget, detector, store, seen_at, link, pass_id, op, decision.why
                )
                done_layers.append(layer_digest)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, dict(cursor), None, {})
        op.settle(cov)
        index = {"indexed": True} if op.index is not None else {}
        if len(done_layers) >= len(layers):
            cov.pass_complete = True
            drop_other_passes(store, self.id, pass_id)
            return SourceRun(cov, {"image": digest, "done": True, **index}, None, {})
        cov.backlog = True
        cursor_out = {"image": digest, "passId": pass_id, "layers": done_layers, "rescan": rescan}
        if indexed:
            cursor_out["indexed"] = True
        return SourceRun(cov, cursor_out, None, {})

    # The read path (`images_read.py`, the `adapter:<kind>` component, #67).
    _members = _read_path._members
    _layer = _read_path._layer
