"""Locate a Terraform resource block by address: given
``iac_address`` (e.g. ``aws_security_group.web`` or
``module.network.aws_security_group.web[0]``), find the file under
``demo/infra`` that declares ``resource "<type>" "<name>" { ... }`` and
extract the exact block text, so it can be validated as ``HclEdit``'s
``original_block`` (must match exactly once).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloudops_orchestrator.integrations.github_client import GithubClient


def parse_resource_address(iac_address: str) -> tuple[str, str]:
    """Terraform resource blocks are always declared as
    ``resource "<type>" "<name>"`` regardless of module nesting or
    ``count``/``for_each`` index, so only the last two dot-separated
    segments of the address matter here."""
    address = iac_address.split("[")[0]  # drop any count/for_each index
    parts = address.split(".")
    if len(parts) < 2:
        msg = f"not a valid Terraform resource address: {iac_address!r}"
        raise ValueError(msg)
    resource_type, resource_name = parts[-2], parts[-1]
    return resource_type, resource_name


def find_resource_block(hcl_text: str, *, resource_type: str, resource_name: str) -> str | None:
    """Return the exact ``resource "type" "name" { ... }`` block text
    (matching braces, skipping braces inside string literals — HCL string
    interpolation like ``"${aws_vpc.main.id}"`` would otherwise unbalance a
    naive brace count), or ``None`` if not found or unbalanced."""
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    match = pattern.search(hcl_text)
    if match is None:
        return None

    start = match.start()
    depth = 0
    in_string = False
    i = match.end() - 1  # the opening '{'
    while i < len(hcl_text):
        char = hcl_text[i]
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return hcl_text[start : i + 1]
        i += 1
    return None  # unbalanced braces: malformed HCL


@dataclass(frozen=True)
class LocatedResource:
    file_path: str
    sha: str
    block: str


def locate_resource(
    client: GithubClient,
    *,
    iac_address: str,
    base_path: str = "demo/infra",
    ref: str | None = None,
) -> LocatedResource | None:
    resource_type, resource_name = parse_resource_address(iac_address)
    for file_path in client.list_terraform_files(base_path, ref=ref):
        content, sha = client.get_file(file_path, ref=ref)
        block = find_resource_block(
            content, resource_type=resource_type, resource_name=resource_name
        )
        if block is not None:
            return LocatedResource(file_path=file_path, sha=sha, block=block)
    return None


__all__ = ["LocatedResource", "find_resource_block", "locate_resource", "parse_resource_address"]
