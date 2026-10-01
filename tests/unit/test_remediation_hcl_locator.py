from __future__ import annotations

from typing import Any

import pytest

from cloudops_orchestrator.remediation.hcl_locator import (
    LocatedResource,
    find_resource_block,
    locate_resource,
    parse_resource_address,
)

HCL_TEXT = """\
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "ssh from \\"anywhere\\""
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "orders-demo-logs"
}
"""


class TestParseResourceAddress:
    def test_simple_address(self) -> None:
        assert parse_resource_address("aws_security_group.web") == ("aws_security_group", "web")

    def test_module_nested_address(self) -> None:
        assert parse_resource_address("module.network.aws_security_group.web") == (
            "aws_security_group",
            "web",
        )

    def test_indexed_address(self) -> None:
        assert parse_resource_address("aws_instance.app[0]") == ("aws_instance", "app")

    def test_invalid_address_raises(self) -> None:
        with pytest.raises(ValueError, match="not a valid Terraform resource address"):
            parse_resource_address("nodots")


class TestFindResourceBlock:
    def test_finds_exact_block(self) -> None:
        block = find_resource_block(
            HCL_TEXT, resource_type="aws_security_group", resource_name="web"
        )
        assert block is not None
        assert block.startswith('resource "aws_security_group" "web" {')
        assert block.endswith("}")
        assert '"aws_s3_bucket"' not in block

    def test_handles_braces_inside_string_literals(self) -> None:
        block = find_resource_block(
            HCL_TEXT, resource_type="aws_security_group", resource_name="web"
        )
        assert block is not None
        assert "ssh from" in block

    def test_finds_second_block(self) -> None:
        block = find_resource_block(HCL_TEXT, resource_type="aws_s3_bucket", resource_name="logs")
        assert block == 'resource "aws_s3_bucket" "logs" {\n  bucket = "orders-demo-logs"\n}'

    def test_missing_resource_returns_none(self) -> None:
        assert (
            find_resource_block(HCL_TEXT, resource_type="aws_instance", resource_name="nope")
            is None
        )

    def test_unbalanced_braces_returns_none(self) -> None:
        text = 'resource "aws_instance" "app" {\n  foo = "bar"\n'
        assert find_resource_block(text, resource_type="aws_instance", resource_name="app") is None


class FakeGithubClient:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def list_terraform_files(self, path: str, *, ref: str | None = None) -> list[str]:
        return sorted(self.files)

    def get_file(self, path: str, *, ref: str | None = None) -> tuple[str, str]:
        return self.files[path], f"sha-{path}"


class TestLocateResource:
    def test_finds_resource_in_second_file(self) -> None:
        client: Any = FakeGithubClient(
            {
                "demo/infra/network.tf": 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
                "demo/infra/sg.tf": HCL_TEXT,
            }
        )
        result = locate_resource(client, iac_address="aws_security_group.web")
        assert result == LocatedResource(
            file_path="demo/infra/sg.tf",
            sha="sha-demo/infra/sg.tf",
            block=find_resource_block(
                HCL_TEXT, resource_type="aws_security_group", resource_name="web"
            ),
        )

    def test_not_found_returns_none(self) -> None:
        client: Any = FakeGithubClient({"demo/infra/sg.tf": HCL_TEXT})
        assert locate_resource(client, iac_address="aws_instance.nonexistent") is None
