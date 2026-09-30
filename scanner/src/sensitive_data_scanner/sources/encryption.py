"""The storage encryption each store's data sits under, as its own configuration says (#35).

Every AWS store names its at-rest key its own way (a bucket's default and each
object's `x-amz-server-side-encryption`, a table's `SSEDescription`, a volume's
`KmsKeyId`, a stream's `EncryptionType`, ...). Each adapter reads that from the
listing it already makes and asks `facts` here for the findings' fields
(`sensitive_data_core.findings.encryption_facts`):

- `none`: the store says its data is not encrypted at rest;
- `service_managed`: a key AWS holds, an AWS owned key (the service's default)
  or an AWS managed key (`aws/s3`, `aws/ebs`, `alias/aws/...`);
- `customer_managed_key`: a KMS key the customer holds, named in the finding
  only by the SHA-256 of its key id (`atRestKeyHash`);
- `unknown`: the store does not say, or its key could not be told apart.

A KMS key named by id or ARN is told apart with **one** `kms:ListAliases` per
run and region: the key ids behind the `alias/aws/*` aliases are AWS managed,
and any other key (including one in another account) is the customer's. Without
that listing only an `alias/aws/...` name is still known; any other key is
`unknown`, with its hash. No key is described, used or named in a finding.
"""

from __future__ import annotations

import re
from typing import Any

from sensitive_data_core.findings import (
    CUSTOMER_MANAGED_KEY,
    NO_ENCRYPTION,
    SERVICE_MANAGED,
    UNKNOWN_ENCRYPTION,
    encryption_facts,
)
from sensitive_data_core.safety import error_name, log_event

# The services this module calls (test_template.py checks every call against them).
AWS_SERVICES = ("kms",)

# Where the per-run classifier is kept among the run's clients (`Clients.services`).
KEYS = "kms-keys"
# A key id (a UUID, or a multi-Region key's `mrk-` and 32 hex digits), bare or in an ARN.
_KEY_ID = re.compile(
    r"^(?:.*:key/)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$"
)
_AWS_ALIAS = re.compile(r"^(?:.*:)?alias/aws/")
_ALIAS = re.compile(r"^(?:.*:)?(alias/.+)$")


class KeyClassifier:
    """Tells an AWS managed KMS key from a customer managed one, by the account's aliases."""

    def __init__(self, clients: Any) -> None:
        self.clients = clients
        self._aws: set[str] | None = None
        self._aliases: dict[str, str] = {}
        self._listed = False

    def _list(self) -> None:
        if self._listed:
            return
        self._listed = True
        try:
            kms = self.clients.client("kms")
            aws: set[str] = set()
            for page in kms.get_paginator("list_aliases").paginate():
                for a in page.get("Aliases", []):
                    name, target = str(a.get("AliasName") or ""), a.get("TargetKeyId")
                    if not target:
                        continue
                    self._aliases[name] = str(target)
                    if name.startswith("alias/aws/"):
                        aws.add(str(target))
            self._aws = aws
        except Exception as err:  # only alias/aws/ names can be told apart then
            log_event("source.failed", source="kms-aliases", error=error_name(err))
            self._aws = None

    def key_id(self, key: str) -> str | None:
        """The key id a key ARN, key id or alias names; None when it cannot be told."""
        k = key.strip()
        m = _KEY_ID.match(k)
        if m:
            return m[1]
        alias = _ALIAS.match(k)
        if alias:
            self._list()
            return self._aliases.get(alias[1])
        return None

    def facts(
        self,
        *,
        encrypted: bool | None = True,
        key: str | None = None,
        aws_owned: bool = False,
    ) -> dict[str, str]:
        """The facts for one store: `encrypted` False is `none`, None (not said) `unknown`;
        encrypted with no `key` named is the service's own key (`aws_owned`, or the default
        when the service says it always encrypts)."""
        if encrypted is False:
            return encryption_facts(NO_ENCRYPTION)
        if not key or aws_owned:
            if encrypted is None:
                return encryption_facts(UNKNOWN_ENCRYPTION)
            return encryption_facts(SERVICE_MANAGED)
        if _AWS_ALIAS.match(key):
            return encryption_facts(SERVICE_MANAGED)
        key_id = self.key_id(key)
        if key_id is None:
            return encryption_facts(UNKNOWN_ENCRYPTION)
        self._list()
        if self._aws is None:
            return encryption_facts(UNKNOWN_ENCRYPTION, key_id)
        if key_id in self._aws:
            return encryption_facts(SERVICE_MANAGED)
        return encryption_facts(CUSTOMER_MANAGED_KEY, key_id)


# The weakest first: what a store of many items says about all of them is its weakest item's.
_STRENGTH = (NO_ENCRYPTION, UNKNOWN_ENCRYPTION, SERVICE_MANAGED, CUSTOMER_MANAGED_KEY)


def weakest(items: list[dict[str, str]]) -> dict[str, str]:
    """A store's facts from its items' (a Parameter Store of SecureString and String
    parameters): the weakest item's encryption, with a key hash only when every item is
    under that one key. No items: `unknown`."""
    if not items:
        return encryption_facts(UNKNOWN_ENCRYPTION)
    low = min(items, key=lambda f: _STRENGTH.index(f.get("atRestEncryption", UNKNOWN_ENCRYPTION)))
    if all(f == low for f in items):
        return dict(low)
    return encryption_facts(low.get("atRestEncryption", UNKNOWN_ENCRYPTION))


def classifier(clients: Any) -> KeyClassifier:
    """The run's classifier, made on first use and kept with its clients."""
    made = clients.services.get(KEYS)
    if made is None:
        made = clients.services[KEYS] = KeyClassifier(clients)
    return made  # type: ignore[no-any-return]


def s3_object_facts(keys: KeyClassifier, response: dict[str, Any]) -> dict[str, str]:
    """An S3 object's own encryption, from its GetObject headers: `AES256` (SSE-S3) is
    `service_managed`, `aws:kms` / `aws:kms:dsse` by the key, and no header at all is an
    object stored before default encryption, not encrypted."""
    sse = response.get("ServerSideEncryption")
    if not sse:
        return encryption_facts(NO_ENCRYPTION)
    if str(sse) == "AES256":
        return encryption_facts(SERVICE_MANAGED)
    return keys.facts(key=response.get("SSEKMSKeyId"))


def s3_bucket_facts(keys: KeyClassifier, rules: list[dict[str, Any]] | None) -> dict[str, str]:
    """A bucket's default encryption (GetBucketEncryption's rules). None: it could not be read."""
    if rules is None:
        return encryption_facts(UNKNOWN_ENCRYPTION)
    for rule in rules:
        d = rule.get("ApplyServerSideEncryptionByDefault") or {}
        algo = str(d.get("SSEAlgorithm") or "")
        if algo == "AES256":
            return encryption_facts(SERVICE_MANAGED)
        if algo.startswith("aws:kms"):
            return keys.facts(key=d.get("KMSMasterKeyID"))
    return encryption_facts(NO_ENCRYPTION)


def dynamodb_facts(keys: KeyClassifier, sse: dict[str, Any] | None) -> dict[str, str]:
    """A table's `SSEDescription`: absent (or disabled) is the AWS owned key; `KMS` is by the
    key (`aws/dynamodb` or the customer's)."""
    if not sse or str(sse.get("Status") or "ENABLED") in ("DISABLED", "DISABLING"):
        return keys.facts(aws_owned=True)
    if str(sse.get("SSEType") or "") == "KMS":
        return keys.facts(key=sse.get("KMSMasterKeyArn"))
    return keys.facts(aws_owned=True)


def rds_facts(keys: KeyClassifier, db: dict[str, Any]) -> dict[str, str]:
    """A DB cluster's or instance's `StorageEncrypted` and `KmsKeyId`."""
    if not db.get("StorageEncrypted"):
        return keys.facts(encrypted=False)
    return keys.facts(key=db.get("KmsKeyId"))


def log_group_facts(keys: KeyClassifier, group: dict[str, Any]) -> dict[str, str]:
    """A log group's `kmsKeyId`, or the service's own encryption (every group is encrypted)."""
    return keys.facts(key=group.get("kmsKeyId"))
