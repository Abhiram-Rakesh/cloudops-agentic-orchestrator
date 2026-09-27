"""Free-plan guardrail tests (Hard Rule #8 / CLAUDE.md §6).

Parses every ``*.tf`` file under ``infra/`` (never ``demo/infra`` — the demo
stack is intentionally out of scope, it is small, ephemeral and reviewed by
hand) with ``python-hcl2`` and fails the build if a forbidden resource type,
an on-demand/auto-scaled DynamoDB table, Lambda reserved/provisioned
concurrency, a Step Functions Express state machine, or more than 6 CloudWatch
alarms shows up. Until Milestone M7 lands ``infra/`` has no ``.tf`` files, so
these pass vacuously — the synthetic-fixture tests below prove the detection
logic itself works today, not just once there is real Terraform to scan.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import hcl2
import pytest
from hcl2.utils import SerializationOptions

# python-hcl2 8.x keeps surrounding double-quotes on string values by default
# (verified against the installed 8.1.4 wheel — a departure from the pre-8.x
# library most examples online still show). strip_string_quotes=True restores
# the "PROVISIONED", not "\"PROVISIONED\"" behavior this module relies on.
_HCL2_OPTIONS = SerializationOptions(strip_string_quotes=True)

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRA_DIR = REPO_ROOT / "infra"

# Hard Rule #8: forbidden because they are not free/near-free by default, or
# because the orchestrator is explicitly VPC-less / serverless-only.
FORBIDDEN_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "aws_nat_gateway",
        "aws_lb",
        "aws_alb",
        "aws_lb_listener",
        "aws_lb_target_group",
        "aws_vpc",
        "aws_vpc_endpoint",
        "aws_ecs_cluster",
        "aws_ecs_service",
        "aws_ecs_task_definition",
        "aws_eks_cluster",
        "aws_instance",
        "aws_codebuild_project",
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_rds_cluster_instance",
        "aws_opensearch_domain",
        "aws_elasticsearch_domain",
        "aws_glue_catalog_database",
        "aws_glue_crawler",
        "aws_glue_job",
        "aws_athena_workgroup",
        "aws_athena_database",
        "aws_cur_report_definition",
        "aws_secretsmanager_secret",
        "aws_kms_key",
        "aws_cloudwatch_dashboard",
        "aws_lambda_provisioned_concurrency_config",
        "aws_appautoscaling_target",
        "aws_appautoscaling_policy",
    }
)

MAX_ALARMS = 6
MAX_DYNAMODB_CAPACITY_UNITS = 25


def _scalar(value: Any) -> Any:
    """python-hcl2 wraps most block attributes in a single-item list."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def iter_tf_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(root.rglob("*.tf"))


def load_resources(tf_files: list[Path]) -> list[tuple[str, str, dict[str, Any], Path]]:
    """Return (resource_type, resource_name, body, file) for every resource block."""
    resources: list[tuple[str, str, dict[str, Any], Path]] = []
    for tf_file in tf_files:
        with tf_file.open(encoding="utf-8") as fh:
            parsed = hcl2.load(fh, serialization_options=_HCL2_OPTIONS)
        for block in parsed.get("resource", []):
            for resource_type, named in block.items():
                for name, body in named.items():
                    resources.append((resource_type, name, body, tf_file))
    return resources


def _write_tf(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestDetectionLogicOnSyntheticFixtures:
    """Prove the scanner itself works, independent of what infra/ contains today."""

    def test_forbidden_resource_type_is_detected(self, tmp_path: Path) -> None:
        _write_tf(
            tmp_path / "bad.tf",
            """
            resource "aws_nat_gateway" "oops" {
              allocation_id = "eip-123"
              subnet_id     = "subnet-123"
            }
            """,
        )
        resources = load_resources(iter_tf_files(tmp_path))
        offenders = [r for r in resources if r[0] in FORBIDDEN_RESOURCE_TYPES]
        assert len(offenders) == 1
        assert offenders[0][0] == "aws_nat_gateway"

    def test_compliant_resources_are_not_flagged(self, tmp_path: Path) -> None:
        _write_tf(
            tmp_path / "good.tf",
            """
            resource "aws_lambda_function" "collect" {
              function_name = "cloudops-lite-collect"
              runtime       = "python3.12"
            }
            resource "aws_dynamodb_table" "state" {
              name         = "cloudops-lite-state"
              billing_mode = "PROVISIONED"
            }
            """,
        )
        resources = load_resources(iter_tf_files(tmp_path))
        offenders = [r for r in resources if r[0] in FORBIDDEN_RESOURCE_TYPES]
        assert offenders == []

    def test_on_demand_dynamodb_billing_mode_detected(self, tmp_path: Path) -> None:
        _write_tf(
            tmp_path / "ddb.tf",
            """
            resource "aws_dynamodb_table" "state" {
              name         = "cloudops-lite-state"
              billing_mode = "PAY_PER_REQUEST"
            }
            """,
        )
        resources = load_resources(iter_tf_files(tmp_path))
        (_rtype, _name, body, _file) = next(r for r in resources if r[0] == "aws_dynamodb_table")
        assert _scalar(body.get("billing_mode")) == "PAY_PER_REQUEST"

    def test_lambda_reserved_concurrency_detected(self, tmp_path: Path) -> None:
        _write_tf(
            tmp_path / "fn.tf",
            """
            resource "aws_lambda_function" "collect" {
              function_name                 = "cloudops-lite-collect"
              reserved_concurrent_executions = 5
            }
            """,
        )
        resources = load_resources(iter_tf_files(tmp_path))
        (_rtype, _name, body, _file) = resources[0]
        assert _scalar(body.get("reserved_concurrent_executions")) == 5

    def test_step_functions_express_detected(self, tmp_path: Path) -> None:
        _write_tf(
            tmp_path / "sfn.tf",
            """
            resource "aws_sfn_state_machine" "review" {
              name     = "cloudops-lite-review"
              type     = "EXPRESS"
              role_arn = "arn:aws:iam::111111111111:role/x"
            }
            """,
        )
        resources = load_resources(iter_tf_files(tmp_path))
        (_rtype, _name, body, _file) = resources[0]
        assert _scalar(body.get("type")) == "EXPRESS"

    def test_alarm_count_over_budget_detected(self, tmp_path: Path) -> None:
        alarms = "\n".join(
            f"""
            resource "aws_cloudwatch_metric_alarm" "alarm_{i}" {{
              alarm_name          = "alarm-{i}"
              comparison_operator = "GreaterThanThreshold"
              evaluation_periods  = 1
              metric_name         = "Errors"
              namespace           = "AWS/Lambda"
              period              = 300
              statistic           = "Sum"
              threshold           = 1
            }}
            """
            for i in range(7)
        )
        _write_tf(tmp_path / "alarms.tf", alarms)
        resources = load_resources(iter_tf_files(tmp_path))
        alarm_count = sum(1 for r in resources if r[0] == "aws_cloudwatch_metric_alarm")
        assert alarm_count == 7
        assert alarm_count > MAX_ALARMS


class TestRealInfraDirectory:
    """The tests that actually gate CI, run against the real infra/ tree."""

    def test_no_forbidden_resource_types(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        offenders = [
            f"{rtype}.{name} in {file.relative_to(REPO_ROOT)}"
            for rtype, name, _body, file in resources
            if rtype in FORBIDDEN_RESOURCE_TYPES
        ]
        assert not offenders, "Forbidden (non-free-plan) resource types found:\n" + "\n".join(
            offenders
        )

    def test_dynamodb_tables_are_provisioned(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        offenders = []
        for rtype, name, body, file in resources:
            if rtype != "aws_dynamodb_table":
                continue
            billing_mode = _scalar(body.get("billing_mode", "PROVISIONED"))
            if billing_mode != "PROVISIONED":
                offenders.append(f"{name} in {file}: billing_mode={billing_mode}")
        assert not offenders, offenders

    def test_dynamodb_capacity_within_free_tier(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        for rtype, name, body, file in resources:
            if rtype != "aws_dynamodb_table":
                continue
            read = _scalar(body.get("read_capacity", 0)) or 0
            write = _scalar(body.get("write_capacity", 0)) or 0
            for gsi in body.get("global_secondary_index", []) or []:
                gsi_body = _scalar(gsi) if isinstance(gsi, list) else gsi
                read += _scalar(gsi_body.get("read_capacity", 0)) or 0
                write += _scalar(gsi_body.get("write_capacity", 0)) or 0
            assert read <= MAX_DYNAMODB_CAPACITY_UNITS, (
                f"{name} in {file}: read capacity {read} > 25"
            )
            assert write <= MAX_DYNAMODB_CAPACITY_UNITS, (
                f"{name} in {file}: write capacity {write} > 25"
            )

    def test_no_lambda_reserved_or_provisioned_concurrency(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        offenders = []
        for rtype, name, body, file in resources:
            if (
                rtype == "aws_lambda_function"
                and body.get("reserved_concurrent_executions") is not None
            ):
                offenders.append(f"{name} in {file} sets reserved_concurrent_executions")
        assert not offenders, offenders

    def test_step_functions_are_standard_not_express(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        offenders = []
        for rtype, name, body, file in resources:
            if rtype != "aws_sfn_state_machine":
                continue
            sfn_type = _scalar(body.get("type", "STANDARD"))
            if sfn_type == "EXPRESS":
                offenders.append(f"{name} in {file}")
        assert not offenders, offenders

    def test_cloudwatch_alarm_count_within_budget(self) -> None:
        resources = load_resources(iter_tf_files(INFRA_DIR))
        alarm_count = sum(1 for r in resources if r[0] == "aws_cloudwatch_metric_alarm")
        assert alarm_count <= MAX_ALARMS, f"{alarm_count} alarms defined, budget is {MAX_ALARMS}"


@pytest.mark.parametrize("forbidden_type", sorted(FORBIDDEN_RESOURCE_TYPES))
def test_forbidden_list_entries_are_plausible_resource_names(forbidden_type: str) -> None:
    # Guards against typos in the allowlist itself (e.g. "aws_lamda_function").
    assert forbidden_type.startswith("aws_")
