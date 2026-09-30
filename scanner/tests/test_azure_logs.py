"""Azure Monitor logs: Log Analytics workspaces sampled with KQL. Stubbed SDK, made-up values."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from azure_fakes import NOW, SUB_A, Arm, AzureError, Graph, Tenant, settings
from sensitive_data_azure.runner import run_scan
from sensitive_data_azure.sources.logs import kql_table, sample_kql
from sensitive_data_core.findings import key_hash
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
RG = f"/subscriptions/{SUB_A}/resourceGroups/rg-ops/providers/Microsoft.OperationalInsights"
WS = f"{RG}/workspaces/law-contoso"
WS2 = f"{RG}/workspaces/law-cmk"
CLUSTER = f"{RG}/clusters/la-cluster"
WS_ID = "0a1b2c3d-0000-4000-8000-000000000001"
SAMPLE = re.compile(r"^\['((?:[^'\\]|\\.)*)'\] \| where TimeGenerated > ago\(\d+d\) \| take (\d+)$")


class Logs:
    """The Log Analytics query API: `Usage`, then one sample per table; queries recorded."""

    def __init__(self, tables: dict[str, list[dict[str, Any]]]) -> None:
        self.tables = tables
        self.queries: list[str] = []
        self.fail: dict[str, Exception] = {}

    def query_workspace(self, workspace_id: str, query: str, **kwargs: Any) -> Any:
        self.queries.append(query)
        assert workspace_id == WS_ID and kwargs["timespan"].days >= 1
        if query.startswith("Usage"):
            rows = [[name] for name in sorted(self.tables)]
            return SimpleNamespace(tables=[SimpleNamespace(columns=["DataType"], rows=rows)])
        m = re.match(
            r"^\['((?:[^'\\]|\\.)*)'\] \| where TimeGenerated > ago\(\d+d\) \| take (\d+)$", query
        )
        assert m, query
        name = m[1].replace("\\'", "'")
        if name in self.fail:
            raise self.fail[name]
        rows_ = self.tables[name][: int(m[2])]
        columns = list(dict.fromkeys(k for r in rows_ for k in r))
        return SimpleNamespace(
            tables=[
                SimpleNamespace(columns=columns, rows=[[r.get(c) for c in columns] for r in rows_])
            ]
        )


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


def tenant(logs: Logs) -> Tenant:
    t = Tenant(
        Graph(
            {
                "operationalinsights/workspaces": [
                    {"id": WS, "name": "law-contoso", "customerId": WS_ID},
                    {"id": WS2, "name": "law-cmk", "customerId": "", "cluster": CLUSTER.lower()},
                ],
                "operationalinsights/clusters": [
                    {
                        "id": CLUSTER.lower(),
                        "vault": "https://kv-ops.vault.azure.net/",
                        "keyName": "la-key",
                    }
                ],
            }
        ),
        Arm(paths={f"{WS}/tables": [{"name": "AppTraces_Basic", "properties": {"plan": "Basic"}}]}),
    )
    t.drivers["_logs"] = logs
    return t


def run(t: Tenant, **env: str) -> dict[str, Any]:
    clients = t.clients()
    clients.made[("logs", "")] = t.drivers["_logs"]
    doc, failed = run_scan(
        settings(DISCOVER="logs", **env), clients, detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def logs() -> Logs:
    return Logs(
        {
            "AppTraces": [
                {"TimeGenerated": "2026-09-29T10:00:00Z", "Message": f"card {CARDS['visa']}"}
            ],
            "AppTraces_Basic": [{"Message": f"card {CARDS['amex']}"}],
            "Custom'CL": [{"ssn_c": dashed(SSN_A), "Note": "x"}],
            "Heartbeat": [{"Computer": "vm-1"}],
        }
    )


def test_tables_with_data_are_sampled_by_column_and_billed_plans_skipped() -> None:
    lg = logs()
    doc = run(tenant(lg))
    s = {x["name"]: x for x in doc["discovery"]["stores"]}
    assert s["law-contoso"]["status"] == "scanned"
    assert s["law-cmk"]["atRestKeyHash"] == key_hash("https://kv-ops.vault.azure.net/keys/la-key")
    assert s["law-contoso"]["atRestEncryption"] == "service_managed"
    cov = next(c for c in doc["coverage"] if c["target"] == "law-contoso")
    assert (cov["listed"], cov["scanned"], cov["skipped"]) == (4, 3, {"billed_plan": 1})
    found = {(f["resource"]["table"], f["resource"]["field"], f["class"]) for f in doc["findings"]}
    assert ("AppTraces", "Message", "card") in found
    assert ("Custom'CL", "ssn_c", "us_ssn") in found
    assert all(f["format"] == "kql" and f["resource"]["readBy"] == "kql" for f in doc["findings"])
    assert not any("AppTraces_Basic" in q for q in lg.queries)
    assert "['Custom\\'CL']" in " ".join(lg.queries)


def test_a_workspace_resumes_at_its_next_table() -> None:
    lg = logs()
    t = tenant(lg)
    run(t, MAX_ITEMS_PER_RUN="1")
    first = [q for q in lg.queries if not q.startswith("Usage")]
    run(t, MAX_ITEMS_PER_RUN="1")
    second = [q for q in lg.queries if not q.startswith("Usage")][len(first) :]
    assert first and second and set(first).isdisjoint(second)


def test_a_workspace_the_identity_cannot_query_is_access_denied() -> None:
    lg = logs()
    t = tenant(lg)
    original = lg.query_workspace

    def denied(workspace_id: str, query: str, **kwargs: Any) -> Any:
        err = AzureError(
            "InsufficientAccessError", "The provided credentials have insufficient access"
        )
        err.status_code = 403  # type: ignore[attr-defined]
        raise err

    lg.query_workspace = denied  # type: ignore[method-assign]
    s = {x["name"]: x for x in run(t)["discovery"]["stores"]}
    assert s["law-contoso"]["reason"] == "access_denied"
    lg.query_workspace = original  # type: ignore[method-assign]


def test_kql_names_are_quoted() -> None:
    assert kql_table("a'b\\c") == "['a\\'b\\\\c']"
    assert sample_kql("T", 3, 10) == "['T'] | where TimeGenerated > ago(3d) | take 10"
