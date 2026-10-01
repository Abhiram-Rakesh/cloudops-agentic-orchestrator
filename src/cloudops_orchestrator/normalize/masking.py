"""Reversible masking of identifiers before anything reaches an LLM prompt.

12-digit account IDs -> ``ACCT_n``; ARNs ->
``ARN_n(service:resource-type)`` (keeps the service and resource type
visible since they matter for reasoning, hides the identifying account/id);
IPv4/IPv6 -> ``IP_n`` (except ``0.0.0.0/0`` and ``::/0``, which are
semantically load-bearing and kept literal); emails -> ``EMAIL_n``; resource
IDs matching ``(sg|i|vol|eipalloc|snap|vpc|subnet)-[0-9a-f]+`` ->
``RID_n(type)``. A ``Masker`` instance is reversible: call ``unmask`` on
whatever the LLM returns before persisting it.

Order matters: ARNs are masked *before* the standalone account-id /
resource-id patterns, because an ARN's text contains both as substrings —
masking those first would shred the ARN into a partially-masked fragment
instead of one clean token.
"""

from __future__ import annotations

import re

_ARN_RE = re.compile(
    r"arn:aws:(?P<service>[a-zA-Z0-9-]+):(?P<region>[a-zA-Z0-9-]*):(?P<account>\d*):(?P<resource>[^\s,)\]\"']+)"
)
_ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b"
)
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}(?:[0-9a-fA-F]{1,4})?(?:/\d{1,3})?\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_RESOURCE_ID_RE = re.compile(
    r"\b(?P<type>sg|i|vol|eipalloc|snap|vpc|subnet)-(?P<id>[0-9a-f]{6,})\b"
)

_RESOURCE_TYPE_NAMES: dict[str, str] = {
    "sg": "security-group",
    "i": "instance",
    "vol": "volume",
    "eipalloc": "eip",
    "snap": "snapshot",
    "vpc": "vpc",
    "subnet": "subnet",
}

_PRESERVE_LITERAL = {"0.0.0.0/0", "::/0"}


class Masker:
    """Stateful, reversible masker.

    One instance masks every finding collected in a run (``steps/collect.py``)
    -- its token<->original mapping must survive to the *later*, separate
    step(s) that call an LLM and need to ``unmask()`` whatever the model
    echoes back (``graph/domain_agent.py``), which in the deployed Lambda
    architecture is a different invocation entirely (``collect`` and
    ``domain_batch`` are separate Lambdas, handed off via S3). Export the
    mapping with ``reverse_map()`` and reconstruct an unmask-only instance
    with ``Masker(reverse=...)`` on the other side — see
    ``steps/serialization.py``'s ``serialize_masker``/``deserialize_masker``.
    """

    def __init__(self, *, reverse: dict[str, str] | None = None) -> None:
        self._counters: dict[str, int] = {}
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = dict(reverse) if reverse is not None else {}

    def reverse_map(self) -> dict[str, str]:
        """This masker's token -> original mapping, for persisting across
        an invocation boundary (see the class docstring)."""
        return dict(self._reverse)

    def _token(self, prefix: str, original: str, *, suffix: str = "") -> str:
        cache_key = f"{prefix}:{original}"
        if cache_key in self._forward:
            return self._forward[cache_key]
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        bare = f"{prefix}_{self._counters[prefix]}"
        token = f"{bare}{suffix}"
        self._forward[cache_key] = token
        self._reverse[token] = original
        if suffix:
            # Confirmed live against a real Anthropic call: a model that's
            # given "RID_2(instance)" sometimes echoes back only "RID_2" in
            # a structured parameter value, reasonably reading "(instance)"
            # as a type annotation rather than part of the identifier. The
            # bare id always maps to exactly one original (counters are
            # per-prefix and monotonic), so this is safe to register
            # unconditionally, not just as an observed workaround.
            self._reverse[bare] = original
        return token

    def _mask_arns(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            service = match.group("service")
            resource = match.group("resource")
            resource_type = re.split(r"[/:]", resource, maxsplit=1)[0]
            return self._token("ARN", match.group(0), suffix=f"({service}:{resource_type})")

        return _ARN_RE.sub(repl, text)

    def _mask_account_ids(self, text: str) -> str:
        return _ACCOUNT_ID_RE.sub(lambda m: self._token("ACCT", m.group(0)), text)

    def _mask_ipv4(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            value = match.group(0)
            if value in _PRESERVE_LITERAL:
                return value
            return self._token("IP", value)

        return _IPV4_RE.sub(repl, text)

    def _mask_ipv6(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            value = match.group(0)
            if value in _PRESERVE_LITERAL or ":" not in value:
                return value
            return self._token("IP", value)

        return _IPV6_RE.sub(repl, text)

    def _mask_emails(self, text: str) -> str:
        return _EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), text)

    def _mask_resource_ids(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            type_name = _RESOURCE_TYPE_NAMES[match.group("type")]
            return self._token("RID", match.group(0), suffix=f"({type_name})")

        return _RESOURCE_ID_RE.sub(repl, text)

    def mask(self, text: str) -> str:
        text = self._mask_arns(text)
        text = self._mask_resource_ids(text)
        text = self._mask_account_ids(text)
        text = self._mask_ipv6(text)
        text = self._mask_ipv4(text)
        text = self._mask_emails(text)
        return text

    def unmask(self, text: str) -> str:
        for token, original in sorted(self._reverse.items(), key=lambda item: -len(item[0])):
            text = text.replace(token, original)
        return text


__all__ = ["Masker"]
