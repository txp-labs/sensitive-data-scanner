"""ECR's read path: one image layer streamed from the URL ECR signs for it, its files read
member by member by the core's reader.

This module is `adapter:ecr` (scripts/components.py): a change here rescans the objects it
read. Listing, discovery and configuration stay in `images.py` (`listing:<kind>`), whose
changes re-list and never re-read (#67).
"""

from __future__ import annotations

import gzip
import io
import tarfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from typing import IO, TYPE_CHECKING, Any

from sensitive_data_core.adapter import Budget, FindingStore
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.index import ObjectPass, Stale, flags_for
from sensitive_data_core.safety import error_name, log_event
from sensitive_data_core.scan.objects import read_object, record
from sensitive_data_core.scan.sniff import MEDIA, SNIFF_BYTES, compatible, declared, sniff

from .exports import merge

if TYPE_CHECKING:
    from .images import EcrSource as _Self

READS = ("ecr",)


def _bytes_fetch(data: bytes) -> Callable[[int, int], bytes]:
    """A ranged fetch over a member's bytes already read from the layer's stream."""
    return lambda start, end: data[start : end + 1]


def _same(resource: dict[str, Any]) -> Callable[[str | None], dict[str, Any]]:
    """The member's resource for every column: a layer's files are named by path only."""
    return lambda _column: resource


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


def _members(src: _Self, stream: IO[bytes], media: str) -> Iterator[tuple[str, IO[bytes], int]]:
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
    src: _Self,
    layer: dict[str, Any],
    cov: Coverage,
    budget: Budget,
    detector: Detector,
    store: FindingStore,
    seen_at: str,
    link: str,
    pass_id: str,
    op: ObjectPass | None = None,
    why: Stale | None = None,
) -> None:
    digest = str(layer.get("digest"))
    # What the layer's files met, for its row in the index (the layer is one object).
    readers: set[str] = set()
    unread: set[str] = set()
    flags = 0
    failed = False
    media = str(layer.get("mediaType") or "")
    url = src.ecr.get_download_url_for_layer(repositoryName=src.repository, layerDigest=digest)[
        "downloadUrl"
    ]
    raw = Capped(src.fetch(str(url), src.max_layer_bytes), src.max_layer_bytes)
    stream = io.BufferedReader(raw, 1024 * 1024)
    files = 0
    try:
        for name, f, size in src._members(stream, media):
            path = name.lstrip("./")
            if path.split("/", 1)[0] in SYSTEM_DIRS:
                continue
            head = f.read(SNIFF_BYTES)
            kind = sniff(head)
            if kind in MEDIA or kind == "binary":
                # Counted by what its bytes are; the stream passes over the rest.
                cov.disguised += int(not compatible(declared(path), kind))
                cov.skipped[kind] = cov.skipped.get(kind, 0) + 1
                unread.add(kind)
                continue
            if files >= src.max_files or not budget.has(size):
                cov.sampled_out += 1
                continue
            data = head + f.read(max(0, src.max_file_bytes - len(head)))
            cov.partial += int(size > src.max_file_bytes)
            budget.take(len(data))
            got = read_object(
                path,
                len(data),
                _bytes_fetch(data),
                detector,
                max_object_bytes=src.max_file_bytes,
                max_inflated_bytes=src.max_inflated_bytes,
                max_rows=0,
                columnar=False,
            )
            resource = store_field_resource(
                service="ecr",
                store=src.repository,
                table=digest[:19],
                field=path,
                read_by="layer_sample",
            )
            readers |= got.readers
            unread |= got.unread
            flags |= flags_for(got)
            findings = record(
                got,
                cov,
                resource_for=_same(resource),
                link=link,
                seen_at=seen_at,
                facts=src.facts,
                offsets=False,
            )
            if findings is None:
                continue
            if op is not None:
                op.rescanned(findings, why)
            files += 1
            for fnd in findings:
                merge(store, f"{src.id}\n{digest}\n{path}", fnd, pass_id)
    except NotImplementedError:
        cov.skipped["archive"] = cov.skipped.get("archive", 0) + 1  # a zstd layer
    except (tarfile.TarError, EOFError, OSError, gzip.BadGzipFile) as err:
        if raw.cut or raw.left <= 0:
            cov.partial += 1  # the byte cap fell inside the layer: what was read stands
        else:
            cov.unreadable += 1
            failed = True
            log_event("item.unreadable", source=src.target, error=error_name(err))
    if raw.cut:
        cov.partial += 1
    if op is not None:
        op.record(
            digest,
            marker=digest,
            readers=tuple(sorted(readers)),
            unread=tuple(sorted(unread)),
            flags=flags,
            unreadable=failed,
        )
