"""CloudFormation templates for the tests: loading, the statements each role holds, and
the policies' sizes as IAM counts them, with the template's intrinsics resolved.

IAM limits (IAM and AWS STS quotas; IAM counts no white space):
- a role's inline policies together: 10,240 characters;
- one managed policy: 6,144 characters;
- managed policies attached to a role: 10 by default (20 with a quota increase).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

INLINE_TOTAL = 10_240
MANAGED_EACH = 6_144
MANAGED_PER_ROLE = 10


class CfnLoader(yaml.SafeLoader):
    """YAML with CloudFormation's short-form tags, as {"Fn::X": value}."""


def _tag(loader: CfnLoader, suffix: str, node: yaml.Node) -> Any:
    name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    if suffix == "GetAtt" and isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node).split(".", 1)}
    if isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {name: loader.construct_sequence(node, deep=True)}
    assert isinstance(node, yaml.MappingNode)
    return {name: loader.construct_mapping(node, deep=True)}


CfnLoader.add_multi_constructor("!", _tag)


def load_path(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load(path.read_text(), Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass
    return data


def load_text(text: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load(text, Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass
    return data


# ------------------------------------------------------------------ what a role holds


def _is_ref_to(value: Any, name: str) -> bool:
    return bool(value == {"Ref": name})


def role_documents(template: dict[str, Any], role: str) -> dict[str, list[tuple[str, Any]]]:
    """The role's policy documents, unresolved: {"inline": [(label, doc)], "managed": [...]}.

    Each label is `Resource` or `Resource/PolicyName`, and a document from a resource
    with a Condition is wrapped as {"Fn::If": [condition, doc, {"Ref": "AWS::NoValue"}]}.
    """
    res = template["Resources"]
    props = res[role].get("Properties", {})
    inline: list[tuple[str, Any]] = []
    managed: list[tuple[str, Any]] = []

    def gated(r: dict[str, Any], doc: Any) -> Any:
        cond = r.get("Condition")
        return {"Fn::If": [cond, doc, {"Ref": "AWS::NoValue"}]} if cond else doc

    for p in props.get("Policies", []):
        inline.append((f"{role}/{p['PolicyName']}", p["PolicyDocument"]))
    # ManagedPolicyArns: a Ref to a policy in the template, maybe under an Fn::If with no
    # else, or an AWS managed policy's ARN.
    attached: dict[str, str | None] = {}
    aws_managed: list[Any] = []
    for entry in props.get("ManagedPolicyArns", []):
        cond, x = None, entry
        if isinstance(entry, dict) and "Fn::If" in entry:
            cond, x, other = entry["Fn::If"]
            assert other == {"Ref": "AWS::NoValue"}, "a managed policy's Fn::If has no else"
        if isinstance(x, dict) and x.get("Ref") in res:
            attached[x["Ref"]] = cond
        else:
            aws_managed.append(x)
    for name, r in res.items():
        t = r["Type"]
        rp = r.get("Properties", {})
        to_role = (t == "AWS::IAM::RolePolicy" and _is_ref_to(rp.get("RoleName"), role)) or (
            t == "AWS::IAM::Policy" and any(_is_ref_to(x, role) for x in rp.get("Roles", []))
        )
        if to_role:
            inline.append((f"{name}/{rp['PolicyName']}", gated(r, rp["PolicyDocument"])))
        elif t == "AWS::IAM::ManagedPolicy" and (
            any(_is_ref_to(x, role) for x in rp.get("Roles", [])) or name in attached
        ):
            if name in attached:
                assert attached[name] == r.get("Condition"), f"{name}: under its own Condition"
            managed.append((name, gated(r, rp["PolicyDocument"])))
    for x in aws_managed:
        managed.append((f"arn:{json.dumps(x)}", None))  # an AWS managed policy: counted only
    return {"inline": inline, "managed": managed}


def statements_with_gates(template: dict[str, Any], role: str) -> list[tuple[list[str], Any]]:
    """Every statement the role can hold, each with the conditions it comes under
    (a resource's Condition, then any Fn::If around the statement), unresolved."""
    out: list[tuple[list[str], Any]] = []
    docs = role_documents(template, role)
    for _, wrapped in docs["inline"] + docs["managed"]:
        if wrapped is None:
            continue
        gates: list[str] = []
        doc = wrapped
        if isinstance(wrapped, dict) and "Fn::If" in wrapped:
            gates = [wrapped["Fn::If"][0]]
            doc = wrapped["Fn::If"][1]
        for raw in doc["Statement"]:
            if isinstance(raw, dict) and "Fn::If" in raw:
                cond, s, other = raw["Fn::If"]
                assert other == {"Ref": "AWS::NoValue"}, "a statement's Fn::If has no else"
                out.append(([*gates, cond], s))
            else:
                out.append((gates, raw))
    return out


def normalized(gates: list[str], s: dict[str, Any]) -> str:
    """One statement as canonical JSON: its gates sorted, action lists as sets."""
    body = dict(s)
    for key in ("Action", "NotAction"):
        if isinstance(body.get(key), list):
            body[key] = sorted(body[key])
    return json.dumps({"gates": sorted(gates), "statement": body}, sort_keys=True)


# ------------------------------------------------------------------ resolving intrinsics


class Resolver:
    """Resolves a template's intrinsics for one set of parameter values.

    Resource references resolve to realistic worst-case strings (the longest partition
    and region, generated names at their maximum length), so sizes are upper bounds.
    """

    PARTITION = "aws-us-gov"
    REGION = "ap-southeast-4"
    ACCOUNT = "111122223333"

    def __init__(self, template: dict[str, Any], params: dict[str, Any]) -> None:
        self.t = template
        self.params: dict[str, Any] = {}
        for name, spec in template.get("Parameters", {}).items():
            value = params.get(name, spec.get("Default", ""))
            if spec.get("Type") == "CommaDelimitedList" and isinstance(value, str):
                value = value.split(",")
            self.params[name] = value
        unknown = set(params) - set(self.params)
        assert not unknown, f"not parameters of the template: {unknown}"
        self._conds: dict[str, bool] = {}

    # CloudFormation generates names of up to 64 characters (roles) or 63 (buckets).
    def ref(self, name: str) -> Any:
        pseudo = {
            "AWS::Partition": self.PARTITION,
            "AWS::Region": self.REGION,
            "AWS::AccountId": self.ACCOUNT,
            "AWS::StackName": "S" * 128,
            "AWS::URLSuffix": "amazonaws.com",
        }
        if name in pseudo:
            return pseudo[name]
        if name in self.params:
            return self.params[name]
        r = self.t["Resources"][name]
        t = r["Type"]
        if t == "AWS::S3::Bucket":
            return "b" * 63
        if t == "AWS::SQS::Queue":
            q = r.get("Properties", {}).get("QueueName", "q" * 80)
            return f"https://sqs.{self.REGION}.amazonaws.com/{self.ACCOUNT}/{q}"
        if t == "AWS::IAM::ManagedPolicy":
            return f"arn:{self.PARTITION}:iam::{self.ACCOUNT}:policy/{'p' * 128}"
        if t == "AWS::IAM::Role":
            return "r" * 64
        return f"{name}-{'x' * 40}"

    def getatt(self, name: str, attr: str) -> str:
        r = self.t["Resources"][name]
        t = r["Type"]
        p, g, a = self.PARTITION, self.REGION, self.ACCOUNT
        assert attr == "Arn", f"{name}.{attr}"
        if t == "AWS::S3::Bucket":
            return f"arn:{p}:s3:::{self.ref(name)}"
        if t == "AWS::Logs::LogGroup":
            lg = r.get("Properties", {}).get("LogGroupName", "l" * 512)
            return f"arn:{p}:logs:{g}:{a}:log-group:{lg}:*"
        if t == "AWS::IAM::Role":
            return f"arn:{p}:iam::{a}:role/{self.ref(name)}"
        if t == "AWS::SQS::Queue":
            q = r.get("Properties", {}).get("QueueName", "q" * 80)
            return f"arn:{p}:sqs:{g}:{a}:{q}"
        if t == "AWS::Lambda::Function":
            fn = r.get("Properties", {}).get("FunctionName", "f" * 64)
            return f"arn:{p}:lambda:{g}:{a}:function:{fn}"
        return f"arn:{p}:{t.split('::')[1].lower()}:{g}:{a}:{name}"

    def condition(self, name: str) -> bool:
        if name not in self._conds:
            self._conds[name] = bool(self.resolve(self.t["Conditions"][name]))
        return self._conds[name]

    def sub(self, text: str, extra: dict[str, Any]) -> str:
        out = ""
        i = 0
        while i < len(text):
            j = text.find("${", i)
            if j < 0:
                out += text[i:]
                break
            out += text[i:j]
            k = text.index("}", j)
            key = text[j + 2 : k]
            if key.startswith("!"):
                out += "${" + key[1:] + "}"
            elif key in extra:
                out += str(extra[key])
            elif "." in key and not key.startswith("AWS::"):
                out += self.getatt(*key.split(".", 1))
            elif key in self.params or key in self.t["Resources"] or key.startswith("AWS::"):
                v = self.ref(key)
                out += ",".join(v) if isinstance(v, list) else str(v)
            else:
                out += "${" + key + "}"  # an IAM policy variable, e.g. ${aws:userid}
            i = k + 1
        return out

    _DROP = object()

    def resolve(self, v: Any) -> Any:
        r = self._resolve(v)
        return None if r is self._DROP else r

    def _resolve(self, v: Any) -> Any:
        if isinstance(v, list):
            items = [self._resolve(x) for x in v]
            return [x for x in items if x is not self._DROP]
        if not isinstance(v, dict):
            return v
        if len(v) == 1:
            ((k, arg),) = v.items()
            if k == "Ref":
                return self._DROP if arg == "AWS::NoValue" else self.ref(arg)
            if k == "Fn::GetAtt":
                return self.getatt(*arg)
            if k == "Fn::Sub":
                if isinstance(arg, str):
                    return self.sub(arg, {})
                text, extra = arg
                return self.sub(text, {n: self._resolve(x) for n, x in extra.items()})
            if k == "Fn::If":
                cond, yes, no = arg
                return self._resolve(yes if self.condition(cond) else no)
            if k == "Fn::Join":
                sep, items = arg
                vals = self._resolve(items)
                return sep.join(str(x) for x in vals)
            if k == "Fn::Split":
                sep, text = arg
                return str(self._resolve(text)).split(sep)
            if k == "Fn::Select":
                idx, items = arg
                return self._resolve(items)[int(self._resolve(idx))]
            if k == "Fn::Equals":
                a, b = (self._resolve(x) for x in arg)
                return str(a) == str(b)
            if k == "Fn::Not":
                return not self._resolve(arg[0])
            if k == "Fn::And":
                return all(self._resolve(x) for x in arg)
            if k == "Fn::Or":
                return any(self._resolve(x) for x in arg)
            if k == "Condition":
                return self.condition(arg)
        out = {}
        for key, x in v.items():
            r = self._resolve(x)
            if r is not self._DROP:
                out[key] = r
        return out


def iam_size(doc: Any) -> int:
    """A policy's size as IAM counts it: its JSON with no white space."""
    text = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    return sum(1 for c in text if not c.isspace())


def role_sizes(template: dict[str, Any], role: str, params: dict[str, Any]) -> dict[str, Any]:
    """{"inline": total, "managed": {name: size}, "count": managed policies attached}."""
    r = Resolver(template, params)
    role_cond = template["Resources"][role].get("Condition")
    if role_cond and not r.condition(role_cond):
        return {"inline": 0, "managed": {}, "count": 0}
    docs = role_documents(template, role)
    inline = 0
    for _, doc in docs["inline"]:
        resolved = r.resolve(doc)
        if resolved is not None:
            inline += iam_size(resolved)
    managed: dict[str, int] = {}
    count = 0
    for name, doc in docs["managed"]:
        if doc is None:
            count += 1
            continue
        resolved = r.resolve(doc)
        if resolved is not None:
            managed[name] = iam_size(resolved)
            count += 1
    return {"inline": inline, "managed": managed, "count": count}
