"""Source code and directory buckets: CodeCommit repositories and S3 Express One Zone (#35).

**CodeCommit** (`DISCOVER` includes `codecommit`): `ListRepositories` and
`GetRepository` (the default branch and its key). For each repository, the
default branch's head (`GetBranch`) is walked folder by folder (`GetFolder`,
at most `CODECOMMIT_MAX_FOLDERS`), and a stable sample of its files, spread
across the tree by a hash of the path, is read (`GetFile`, at most
`CODECOMMIT_MAX_FILES`, each up to `MAX_OBJECT_BYTES`), by the core's reader
(`scan/objects.py`), as S3 reads them: by what the file's bytes are, not its
name, so audio, video, images and binary files are counted, not read; Word,
Excel and PowerPoint files, PDFs and archives (zip, tar, gzip, bzip2, xz) are
read as their text and by entry, up to `MAX_INFLATED_BYTES` inflated. A
finding names the repository and the file's path (and, in an archive, the
entry's: `archivePath`). A pass resumes across runs, and starts
over when the branch moves. Nothing is pushed or merged; the role denies it.

**S3 directory buckets** (`s3_directory`): `ListDirectoryBuckets`, then each
bucket read like any other by the S3 source (`express`), through S3 Express
sessions the scanner creates **read-only** (`CreateSession` with
`SessionMode=ReadOnly`, the only mode its role may ask for).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
import urllib.parse
from typing import Any

from sensitive_data_core.adapter import Budget, FindingStore, SourceRun
from sensitive_data_core.coverage import Discovery, Store, reason_for
from sensitive_data_core.detect.analyzer import Detector
from sensitive_data_core.findings import Coverage, store_field_resource
from sensitive_data_core.safety import error_name, is_kms_denial, log_event
from sensitive_data_core.scan.objects import planned_bytes, read_object, record, sample_point

from ..discovery import decide, needs_tags
from ..resources import console_link
from .base import Context
from .encryption import classifier
from .exports import drop_other_passes, merge
from .s3 import S3Source

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("codecommit", "s3")


# ------------------------------------------------------------------ CodeCommit


class CodeCommitAdapter:
    kind = "codecommit"

    def discover(self, ctx: Context, out: Discovery) -> None:
        cc = ctx.clients.client("codecommit")
        keys = classifier(ctx.clients)
        for page in cc.get_paginator("list_repositories").paginate():
            for r in page.get("repositories", []):
                name = str(r["repositoryName"])
                store = Store(self.kind, name)
                out.stores.append(store)
                try:
                    meta = cc.get_repository(repositoryName=name)["repositoryMetadata"]
                except Exception as err:
                    store.status, store.error = "error", error_name(err)
                    store.reason = reason_for(store.error)
                    continue
                tag_error: str | None = None
                if needs_tags(ctx.config, self.kind):
                    try:
                        t = cc.list_tags_for_resource(resourceArn=str(meta.get("Arn")))
                        store.tags = {str(k): str(v) for k, v in (t.get("tags") or {}).items()}
                    except Exception as err:
                        tag_error = error_name(err)
                decide(store, ctx.config, tag_error)
                if store.status != "pending":
                    continue
                if not meta.get("defaultBranch"):
                    store.skip("unsupported")  # an empty repository: no branch to read
                    store.extra["state"] = "empty"
                    continue
                store.extra["branch"] = str(meta["defaultBranch"])
                key = meta.get("kmsKeyId")
                store.facts = keys.facts(key=key, aws_owned=not key)

    def source(self, ctx: Context, store: Store) -> CodeCommitSource | None:
        branch = store.extra.get("branch")
        if not branch:
            return None
        c = ctx.config
        return CodeCommitSource(
            ctx.clients.client("codecommit"),
            repository=store.name,
            branch=str(branch),
            region=ctx.region,
            max_files=c.codecommit_max_files,
            max_folders=c.codecommit_max_folders,
            max_bytes=c.max_object_bytes,
            max_inflated_bytes=c.max_inflated_bytes,
        )


class CodeCommitSource:
    """One repository's default branch at its head: a stable sample of its files."""

    kind = "codecommit"
    facts: dict[str, Any] | None = None

    def __init__(
        self,
        client: Any,
        *,
        repository: str,
        branch: str,
        region: str,
        max_files: int = 200,
        max_folders: int = 500,
        max_bytes: int = 20 * 1024**2,
        max_inflated_bytes: int = 100 * 1024**2,
    ) -> None:
        self.client = client
        self.repository = repository
        self.branch = branch
        self.region = region
        self.max_files = max_files
        self.max_folders = max_folders
        self.max_bytes = max_bytes
        self.max_inflated_bytes = max_inflated_bytes
        self.id = f"codecommit:{hashlib.sha256(repository.encode()).hexdigest()[:16]}"
        self.target = repository

    def link(self) -> str:
        q = urllib.parse.quote(self.repository, safe="")
        return console_link(
            self.region, f"codesuite/codecommit/repositories/{q}/browse?region={self.region}"
        )

    def _files(self, commit: str, cov: Coverage) -> list[str]:
        """Every file path at `commit`, folder by folder, up to the folder cap."""
        files: list[str] = []
        folders, walked = ["/"], 0
        while folders and walked < self.max_folders:
            path = folders.pop()
            walked += 1
            r = self.client.get_folder(
                repositoryName=self.repository, commitSpecifier=commit, folderPath=path
            )
            files.extend(str(f["absolutePath"]) for f in r.get("files", []))
            folders.extend(str(f["absolutePath"]) for f in r.get("subFolders", []))
        if folders:
            cov.partial += 1  # more folders than the cap: the sample is of the ones walked
        return files

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
            head = self.client.get_branch(repositoryName=self.repository, branchName=self.branch)
            commit = str(head["branch"]["commitId"])
            same = cursor.get("commit") == commit
            if same and cursor.get("done"):
                cov.pass_complete = True  # the head has not moved since the last full pass
                return SourceRun(cov, dict(cursor), None, {})
            pass_id = str(cursor.get("passId")) if same else secrets.token_hex(8)
            after = int(cursor.get("after") or 0) if same else 0
            paths = self._files(commit, cov)
            cov.listed = len(paths)
            # Every file is a candidate: what it is is decided by its bytes, not its name.
            readable = paths
            # A stable sample spread across the tree: the same files every pass.
            sample = sorted(readable, key=lambda p: (sample_point(p), p))[: self.max_files]
            cov.eligible = len(sample)
            cov.sampled_out = len(readable) - len(sample)
            if cov.sampled_out:
                cov.sample_percent = max(1, round(100 * len(sample) / max(1, len(readable))))
            i = after
            for i in range(after, len(sample)):
                if not budget.has(0):
                    break
                self._read(
                    sample[i],
                    commit,
                    cov=cov,
                    budget=budget,
                    detector=detector,
                    store=store,
                    seen_at=seen_at,
                    link=link,
                    pass_id=pass_id,
                )
            else:
                i = len(sample)
        except Exception as err:  # recorded by name on the source
            cov.error = error_name(err)
            if is_kms_denial(err):
                cov.kms_denied += 1
            log_event("source.failed", source=self.target, error=cov.error)
            return SourceRun(cov, dict(cursor), None, {})
        if i >= len(sample):
            cov.pass_complete = True
            gone = drop_other_passes(store, self.id, pass_id)
            if gone:
                log_event("finding.gone", source=self.target, count=gone)
            return SourceRun(cov, {"commit": commit, "done": True}, None, {})
        cov.backlog = True
        return SourceRun(cov, {"commit": commit, "passId": pass_id, "after": i}, None, {})

    def _read(
        self,
        path: str,
        commit: str,
        *,
        cov: Coverage,
        budget: Budget,
        detector: Detector,
        store: FindingStore,
        seen_at: str,
        link: str,
        pass_id: str,
    ) -> None:
        try:
            r = self.client.get_file(
                repositoryName=self.repository, commitSpecifier=commit, filePath=path
            )
        except Exception as err:  # one file must not stop the pass
            cov.unreadable += 1
            log_event("item.unreadable", source=self.target, error=error_name(err))
            return
        data = bytes(r.get("fileContent") or b"")
        budget.take(planned_bytes(path, len(data), self.max_bytes))
        got = read_object(
            path,
            len(data),
            lambda start, end: data[start : end + 1],
            detector,
            max_object_bytes=self.max_bytes,
            max_inflated_bytes=self.max_inflated_bytes,
            max_rows=0,
            columnar=False,
        )
        findings = record(
            got,
            cov,
            resource_for=lambda _column: store_field_resource(
                service="codecommit", store=self.repository, field=path, read_by="get_file"
            ),
            link=link,
            seen_at=seen_at,
            facts=self.facts,
            offsets=False,
        )
        for f in findings or []:
            merge(store, f"{self.id}\n{path}", f, pass_id)


# ------------------------------------------------------------------ S3 directory buckets


def read_only_sessions(client: Any) -> Any:
    """Every S3 Express session this client creates is read-only (`SessionMode=ReadOnly`):
    botocore creates them itself before a directory bucket's GET or LIST."""

    def read_only(params: dict[str, Any], **_: Any) -> None:
        params["SessionMode"] = "ReadOnly"

    # First, so no other handler sees the request before it is read-only.
    client.meta.events.register_first(
        "before-parameter-build.s3.CreateSession", read_only, unique_id="sds-read-only-session"
    )
    return client


class DirectoryBucketAdapter:
    kind = "s3_directory"

    def discover(self, ctx: Context, out: Discovery) -> None:
        s3 = ctx.clients.client("s3")
        token: str | None = None
        while True:
            r = s3.list_directory_buckets(**({"ContinuationToken": token} if token else {}))
            for b in r.get("Buckets", []):
                store = Store(self.kind, str(b["Name"]))
                out.stores.append(store)
                if store.name == ctx.config.results_bucket:
                    store.skip("self")
                    continue
                decide(store, ctx.config)
            token = r.get("ContinuationToken")
            if not token:
                break

    def source(self, ctx: Context, store: Store) -> S3Source:
        c = ctx.config
        return S3Source(
            read_only_sessions(ctx.clients.client("s3")),
            bucket=store.name,
            prefix="",
            region=ctx.region,
            sample_percent=store.sample_percent or c.sample_percent,
            max_object_bytes=c.max_object_bytes,
            max_inflated_bytes=c.max_inflated_bytes,
            skew_seconds=c.s3_skew_seconds,
            max_per_prefix=store.max_per_prefix
            if store.max_per_prefix is not None
            else c.s3_max_objects_per_prefix,
            max_rows=c.columnar_max_rows,
            keys=classifier(ctx.clients),
            express=True,
        )
