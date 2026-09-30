"""Cosmos DB (NoSQL, the other APIs, MongoDB vCore), Table Storage and Queue Storage.

Stubbed Azure SDK clients and a stubbed pymongo; every value is made up.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from jsonschema import Draft202012Validator

from aws_fixtures import shared_detector
from azure_fakes import NOW, SUB_A, TOKEN, Arm, AzureError, Graph, Tenant, account_row, settings
from db_fakes import Collection, MongoClient, MongoDb, MongoDriver, read_only_mongo_status
from sensitive_data_azure.runner import run_scan
from sensitive_data_azure.sources.common import message_text
from sensitive_data_azure.sources.databases import OSSRDBMS_SCOPE
from sensitive_data_core.findings import key_hash
from synthetic import CARDS, SSN_A, dashed

REPO = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(
    json.loads((REPO / "schema" / "findings.schema.json").read_text()),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
RG = f"/subscriptions/{SUB_A}/resourceGroups/rg-app/providers"
COSMOS = f"{RG}/Microsoft.DocumentDB/databaseAccounts/cosmos-contoso"
COSMOS_MONGO = f"{RG}/Microsoft.DocumentDB/databaseAccounts/cosmos-legacy"
VCORE = f"{RG}/Microsoft.DocumentDB/mongoClusters/vcore-contoso"
VCORE_NATIVE = f"{RG}/Microsoft.DocumentDB/mongoClusters/vcore-native"
STORAGE = f"{RG}/Microsoft.Storage/storageAccounts/contosoapp"
COSMOS_KEY = "https://kv-contoso.vault.azure.net/keys/cosmos-key"


def valid(doc: dict[str, Any]) -> None:
    errors = [f"{list(e.path)}: {e.message}" for e in SCHEMA.iter_errors(doc)]
    assert errors == []


class Items:
    """A Cosmos container: `query_items` answers, and every query is recorded."""

    def __init__(self, items: list[dict[str, Any]], fail: Exception | None = None) -> None:
        self.items = items
        self.fail = fail
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def query_items(self, query: str, **kwargs: Any) -> Any:
        self.queries.append((query, kwargs))
        if self.fail is not None:
            raise self.fail
        return iter(self.items)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"a Cosmos container was asked to {name}")


class Cosmos:
    def __init__(self, containers: dict[tuple[str, str], Items]) -> None:
        self.containers = containers

    def get_database_client(self, db: str) -> Any:
        return SimpleNamespace(get_container_client=lambda c: self.containers[(db, c)])


class Table:
    def __init__(self, entities: list[dict[str, Any]], fail: Exception | None = None) -> None:
        self.entities = entities
        self.fail = fail

    def list_entities(self, results_per_page: int | None = None, **kwargs: Any) -> Any:
        if self.fail is not None:
            raise self.fail
        return iter(self.entities)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"a table was asked to {name}")


class Queue:
    """Peek only: any other call on a queue fails the test."""

    def __init__(self, messages: list[Any], fail: Exception | None = None) -> None:
        self.messages = messages
        self.fail = fail
        self.peeks: list[int | None] = []

    def peek_messages(self, max_messages: int | None = None, **kwargs: Any) -> list[Any]:
        self.peeks.append(max_messages)
        if self.fail is not None:
            raise self.fail
        return [SimpleNamespace(content=m, dequeue_count=0) for m in self.messages]

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"a queue was asked to {name}")


class Service:
    def __init__(self, **children: Any) -> None:
        self.children = children

    def get_table_client(self, name: str) -> Any:
        return self.children[name]

    def get_queue_client(self, name: str) -> Any:
        return self.children[name]


def tenant() -> Tenant:
    g = Graph(
        {
            "databaseaccounts": [
                {
                    "id": COSMOS,
                    "name": "cosmos-contoso",
                    "kind": "GlobalDocumentDB",
                    "endpoint": "https://cosmos-contoso.documents.azure.com:443/",
                    "capabilities": [],
                    "keyUri": COSMOS_KEY,
                },
                {
                    "id": COSMOS_MONGO,
                    "name": "cosmos-legacy",
                    "kind": "MongoDB",
                    "capabilities": [{"name": "EnableMongo"}],
                    "publicNetworkAccess": "Disabled",
                },
            ],
            "mongoclusters": [
                {"id": VCORE, "name": "vcore-contoso", "authModes": ["MicrosoftEntraID"]},
                {"id": VCORE_NATIVE, "name": "vcore-native", "authModes": ["NativeAuth"]},
            ],
            "storageaccounts": [account_row("contosoapp", group="rg-app")],
        },
        page=10,
    )
    t = Tenant(
        g,
        Arm(
            paths={
                f"{COSMOS}/sqlDatabases": [{"name": "crm"}],
                f"{COSMOS}/sqlDatabases/crm/containers": [{"name": "people"}],
                f"{STORAGE}/tableServices/default/tables": [{"name": "customers"}],
                f"{STORAGE}/queueServices/default/queues": [{"name": "orders"}, {"name": "raw"}],
            }
        ),
    )
    people = Items(
        [
            {
                "id": "1",
                "cardNumber": CARDS["visa"],
                "profile": {"ssn": dashed(SSN_A)},
                "_rid": "abc==",
                "_ts": 1790000000,
            }
        ]
    )
    t.clients_made = {  # type: ignore[attr-defined]
        ("cosmos", "https://cosmos-contoso.documents.azure.com:443/"): Cosmos(
            {("crm", "people"): people}
        ),
        ("table", "https://contosoapp.table.core.windows.net/"): Service(
            customers=Table(
                [{"PartitionKey": "p", "RowKey": "1", "card_number": CARDS["mastercard"]}]
            )
        ),
        ("queue", "https://contosoapp.queue.core.windows.net/"): Service(
            orders=Queue(
                [
                    json.dumps({"card": CARDS["amex"], "note": "x"}),
                    base64.b64encode(f"ssn {dashed(SSN_A)}".encode()).decode(),
                ]
            ),
            raw=Queue([], fail=AzureError("AuthorizationPermissionMismatch", "no queue role")),
        ),
    }
    mongo = MongoClient(
        {"crm": MongoDb({"people": Collection([{"card": CARDS["discover"]}])})},
        read_only_mongo_status(),
    )
    t.drivers["pymongo"] = MongoDriver(mongo)
    return t


def run(t: Tenant, **env: str) -> dict[str, Any]:
    clients = t.clients()
    clients.made.update(t.clients_made)  # type: ignore[attr-defined]
    doc, failed = run_scan(
        settings(DISCOVER="all", **env), clients, detector=shared_detector(), now=lambda: NOW
    )
    assert doc is not None and failed == 0
    valid(doc)
    return doc


def stores(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f"{s['kind']}:{s['name']}": s for s in doc["discovery"]["stores"]}


def test_cosmos_nosql_is_read_with_one_top_query() -> None:
    t = tenant()
    doc = run(t)
    s = stores(doc)
    people = s["cosmosdb:cosmos-contoso/crm/people"]
    assert people["status"] == "scanned" and people["api"] == "sql"
    assert people["atRestKeyHash"] == key_hash(COSMOS_KEY)
    legacy = s["cosmosdb:cosmos-legacy/*"]
    assert (legacy["reason"], legacy["api"], legacy["networkRestricted"]) == (
        "no_read_path",
        "mongodb",
        True,
    )
    container = t.clients_made[  # type: ignore[attr-defined]
        ("cosmos", "https://cosmos-contoso.documents.azure.com:443/")
    ].containers[("crm", "people")]
    query, kwargs = container.queries[0]
    assert query == "SELECT TOP @n * FROM c" and kwargs["parameters"][0]["value"] == 1000
    assert kwargs["enable_cross_partition_query"] is True
    cosmos = [f for f in doc["findings"] if f["resource"]["service"] == "cosmosdb"]
    assert {(f["resource"]["field"], f["class"]) for f in cosmos} >= {
        ("cardNumber", "card"),
        ("profile", "us_ssn"),
    }
    assert all(f["resource"]["readBy"] == "query" for f in cosmos)
    assert all(f["atRestEncryption"] == "customer_managed_key" for f in cosmos)
    assert not any(f["resource"]["field"].startswith("_") for f in cosmos)


def test_a_cosmos_403_says_role_or_network() -> None:
    t = tenant()
    c = t.clients_made[  # type: ignore[attr-defined]
        ("cosmos", "https://cosmos-contoso.documents.azure.com:443/")
    ].containers[("crm", "people")]
    denied = AzureError("Forbidden", "principal does not have required RBAC permissions")
    denied.status_code = 403  # type: ignore[attr-defined]
    c.fail = denied
    s = stores(run(t))
    assert s["cosmosdb:cosmos-contoso/crm/people"]["reason"] == "access_denied"
    blocked = AzureError("Forbidden", "Request blocked by your Cosmos DB account firewall")
    blocked.status_code = 403  # type: ignore[attr-defined]
    c.fail = blocked
    s = stores(run(t))
    assert s["cosmosdb:cosmos-contoso/crm/people"]["reason"] == "network"


def test_tables_are_sampled_and_queues_only_peeked() -> None:
    t = tenant()
    doc = run(t)
    s = stores(doc)
    assert s["azure_table:contosoapp/customers"]["status"] == "scanned"
    assert s["azure_queue:contosoapp/orders"]["status"] == "scanned"
    assert s["azure_queue:contosoapp/raw"]["reason"] == "access_denied"
    table = [f for f in doc["findings"] if f["resource"]["service"] == "azure_table"]
    assert [(f["resource"]["field"], f["class"]) for f in table] == [("card_number", "card")]
    queue = {f["class"]: f for f in doc["findings"] if f["resource"]["service"] == "azure_queue"}
    assert set(queue) >= {"card", "us_ssn"}  # the base64 message decoded
    assert queue["card"]["resource"]["field"] == "messages"
    assert queue["card"]["resource"]["readBy"] == "peek"
    orders = t.clients_made[  # type: ignore[attr-defined]
        ("queue", "https://contosoapp.queue.core.windows.net/")
    ].children["orders"]
    assert orders.peeks == [32]


def test_mongodb_vcore_is_read_as_the_identity_when_opted_in() -> None:
    t = tenant()
    s = stores(run(t))
    assert s["cosmosdb_mongo:vcore-contoso/*"]["reason"] == "read_not_configured"
    assert s["cosmosdb_mongo:vcore-native/*"]["reason"] == "no_read_path"
    doc = run(t, AZURE_DB_READ="mongo")
    s = stores(doc)
    assert s["cosmosdb_mongo:vcore-contoso/*"]["status"] == "scanned"
    found = [f for f in doc["findings"] if f["resource"]["service"] == "cosmosdb_mongo"]
    assert found and found[0]["resource"]["table"] == "people"
    args, kwargs = t.drivers["pymongo"].calls[0]
    assert "authMechanism=MONGODB-OIDC" in args[0] and "vcore-contoso" in args[0]
    callback = kwargs["authMechanismProperties"]["OIDC_CALLBACK"]
    assert callback.fetch(None).access_token == TOKEN
    assert OSSRDBMS_SCOPE in t.credential.scopes


def test_a_vcore_user_that_can_write_is_refused() -> None:
    t = tenant()
    status = read_only_mongo_status()
    status["authInfo"]["authenticatedUserPrivileges"][0]["actions"].append("insert")
    t.drivers["pymongo"].client.admin.status = status
    s = stores(run(t, AZURE_DB_READ="mongo"))
    vcore = s["cosmosdb_mongo:vcore-contoso/*"]
    assert (vcore["reason"], vcore["writeGrants"]) == ("db_user_can_write", ["insert"])


def test_message_text_decodes_base64_only_when_it_gives_text() -> None:
    assert message_text(base64.b64encode(b"hello world").decode()) == "hello world"
    assert message_text("plain text message") == "plain text message"
    assert message_text(b"\x00\x01binary") is None
