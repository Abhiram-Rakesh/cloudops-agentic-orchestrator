"""``cloudops doctor``: read-only health checks, run by a human
against a real deployed account.

Every check is isolated and defensive — one API being unavailable,
access-denied, or simply not existing on this account/plan degrades that
one check to WARN/SKIP with a note, never crashes the whole command. This
follows the same principle for Titan access (warn-only; retrieval degrades
gracefully).
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class CheckStatus(StrEnum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: CheckStatus
    detail: str


def _run(name: str, fn: Callable[[], DoctorCheck]) -> DoctorCheck:
    try:
        return fn()
    except Exception as exc:
        return DoctorCheck(name, CheckStatus.FAIL, f"{type(exc).__name__}: {exc}")


def check_sts_identity(sts_client: Any) -> DoctorCheck:
    def _check() -> DoctorCheck:
        identity = sts_client.get_caller_identity()
        return DoctorCheck(
            "sts_identity", CheckStatus.OK, f"Account {identity['Account']}, ARN {identity['Arn']}"
        )

    return _run("sts_identity", _check)


def check_dynamodb_tables(dynamodb_client: Any, table_names: list[str]) -> DoctorCheck:
    def _check() -> DoctorCheck:
        total_read = 0
        total_write = 0
        for table_name in table_names:
            table = dynamodb_client.describe_table(TableName=table_name)["Table"]
            billing_mode = table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
            if billing_mode != "PROVISIONED":
                return DoctorCheck(
                    "dynamodb_tables",
                    CheckStatus.FAIL,
                    f"{table_name} is billing_mode={billing_mode}, not PROVISIONED",
                )
            throughput = table.get("ProvisionedThroughput", {})
            total_read += throughput.get("ReadCapacityUnits", 0)
            total_write += throughput.get("WriteCapacityUnits", 0)
            for gsi in table.get("GlobalSecondaryIndexes", []):
                gsi_throughput = gsi.get("ProvisionedThroughput", {})
                total_read += gsi_throughput.get("ReadCapacityUnits", 0)
                total_write += gsi_throughput.get("WriteCapacityUnits", 0)
        return DoctorCheck(
            "dynamodb_tables",
            CheckStatus.OK,
            f"{len(table_names)} table(s) PROVISIONED, read={total_read} write={total_write}",
        )

    return _run("dynamodb_tables", _check)


def check_ssm_parameters(ssm_client: Any, parameter_names: list[str]) -> DoctorCheck:
    def _check() -> DoctorCheck:
        missing: list[str] = []
        placeholders: list[str] = []
        for name in parameter_names:
            try:
                response = ssm_client.get_parameter(Name=name, WithDecryption=True)
            except ssm_client.exceptions.ParameterNotFound:
                missing.append(name)
                continue
            if response["Parameter"]["Value"] == "CHANGE_ME":
                placeholders.append(name)
        if missing:
            return DoctorCheck("ssm_parameters", CheckStatus.FAIL, f"Missing: {', '.join(missing)}")
        if placeholders:
            return DoctorCheck(
                "ssm_parameters", CheckStatus.WARN, f"Still CHANGE_ME: {', '.join(placeholders)}"
            )
        return DoctorCheck(
            "ssm_parameters", CheckStatus.OK, f"All {len(parameter_names)} parameter(s) set"
        )

    return _run("ssm_parameters", _check)


def check_titan_access(
    bedrock_client: Any, *, model_id: str = "amazon.titan-embed-text-v2:0"
) -> DoctorCheck:
    def _check() -> DoctorCheck:
        try:
            bedrock_client.get_foundation_model(modelIdentifier=model_id)
        except Exception as exc:
            return DoctorCheck(
                "titan_access",
                CheckStatus.WARN,
                f"{model_id} not confirmed ({exc}) — kb.query_embeddings: none keeps retrieval working",
            )
        return DoctorCheck(
            "titan_access",
            CheckStatus.OK,
            f"{model_id} is listed (does not confirm this account's Model Access is enabled for it)",
        )

    return _run("titan_access", _check)


def check_security_trial(
    *,
    securityhub_client: Any,
    guardduty_client: Any,
    config_client: Any,
    trial_start_date: str,
    now: datetime | None = None,
) -> DoctorCheck:
    def _check() -> DoctorCheck:
        now_ = now or datetime.now(UTC)
        started = datetime.fromisoformat(f"{trial_start_date}T00:00:00+00:00")
        days_elapsed = (now_ - started).days
        days_remaining = 30 - days_elapsed

        statuses = []
        try:
            securityhub_client.describe_hub()
            statuses.append("Security Hub: enabled")
        except Exception:
            statuses.append("Security Hub: not enabled")
        try:
            detectors = guardduty_client.list_detectors().get("DetectorIds", [])
            statuses.append(f"GuardDuty: {'enabled' if detectors else 'not enabled'}")
        except Exception:
            statuses.append("GuardDuty: not enabled")
        try:
            recorders = config_client.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            statuses.append(f"Config: {'enabled' if recorders else 'not enabled'}")
        except Exception:
            statuses.append("Config: not enabled")

        status = CheckStatus.WARN if days_remaining <= 5 else CheckStatus.OK
        return DoctorCheck(
            "security_trial",
            status,
            f"{'; '.join(statuses)}. Trial day {days_elapsed}, {days_remaining} day(s) until the 30-day trial window ends.",
        )

    return _run("security_trial", _check)


def check_cost_explorer(ce_client: Any) -> DoctorCheck:
    def _check() -> DoctorCheck:
        monitors = ce_client.get_anomaly_monitors().get("AnomalyMonitors", [])
        if not monitors:
            return DoctorCheck("cost_explorer", CheckStatus.WARN, "No Cost Anomaly monitors found")
        return DoctorCheck(
            "cost_explorer", CheckStatus.OK, f"{len(monitors)} anomaly monitor(s) found"
        )

    return _run("cost_explorer", _check)


def check_kb_index(s3_client: Any, *, bucket: str, key: str) -> DoctorCheck:
    def _check() -> DoctorCheck:
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
        except s3_client.exceptions.NoSuchKey:
            return DoctorCheck("kb_index", CheckStatus.FAIL, f"s3://{bucket}/{key} not found")
        body = gzip.decompress(response["Body"].read())
        index = json.loads(body)
        return DoctorCheck(
            "kb_index", CheckStatus.OK, f"kb_version={index.get('kb_version', 'unknown')}"
        )

    return _run("kb_index", _check)


def check_artifact_freshness(
    s3_client: Any, *, bucket: str, key: str, max_age_days: int, now: datetime | None = None
) -> DoctorCheck:
    def _check() -> DoctorCheck:
        now_ = now or datetime.now(UTC)
        try:
            response = s3_client.head_object(Bucket=bucket, Key=key)
        except Exception as exc:
            return DoctorCheck(key, CheckStatus.WARN, f"s3://{bucket}/{key} not found ({exc})")
        age_days = (now_ - response["LastModified"]).days
        if age_days > max_age_days:
            return DoctorCheck(
                key, CheckStatus.WARN, f"s3://{bucket}/{key} is {age_days} day(s) old"
            )
        return DoctorCheck(key, CheckStatus.OK, f"s3://{bucket}/{key} is {age_days} day(s) old")

    return _run(key, _check)


def check_slack_auth(slack_client: Any) -> DoctorCheck:
    def _check() -> DoctorCheck:
        response = slack_client.auth_test()
        return DoctorCheck(
            "slack_auth", CheckStatus.OK, f"Authenticated as {response.get('user', 'unknown')}"
        )

    return _run("slack_auth", _check)


def check_github_token(github_client: Any, *, owner: str, repo: str) -> DoctorCheck:
    def _check() -> DoctorCheck:
        github_client.get_default_branch()
        return DoctorCheck("github_token", CheckStatus.OK, f"Can read {owner}/{repo}")

    return _run("github_token", _check)


def check_langsmith_key(ssm_client: Any, *, parameter_name: str) -> DoctorCheck:
    def _check() -> DoctorCheck:
        response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        if response["Parameter"]["Value"] == "CHANGE_ME":
            return DoctorCheck("langsmith_key", CheckStatus.WARN, "Still CHANGE_ME")
        return DoctorCheck("langsmith_key", CheckStatus.OK, "Set")

    return _run("langsmith_key", _check)


def check_state_machine_and_schedule(scheduler_client: Any, *, name_prefix: str) -> DoctorCheck:
    def _check() -> DoctorCheck:
        # state machine ARN isn't known without the account ID; callers
        # that need an exact ARN should call describe_state_machine
        # themselves — this check just confirms the schedule exists, which
        # is enough to catch "deploy.yml never ran" style gaps.
        schedule = scheduler_client.get_schedule(Name=f"{name_prefix}-weekly-review")
        state = schedule.get("State", "UNKNOWN")
        return DoctorCheck("state_machine_schedule", CheckStatus.OK, f"Schedule state={state}")

    return _run("state_machine_schedule", _check)


def check_budgets(budgets_client: Any, *, account_id: str) -> DoctorCheck:
    def _check() -> DoctorCheck:
        budgets = budgets_client.describe_budgets(AccountId=account_id).get("Budgets", [])
        if not budgets:
            return DoctorCheck("budgets", CheckStatus.WARN, "No budgets found")
        return DoctorCheck("budgets", CheckStatus.OK, f"{len(budgets)} budget(s) found")

    return _run("budgets", _check)


__all__ = [
    "CheckStatus",
    "DoctorCheck",
    "check_artifact_freshness",
    "check_budgets",
    "check_cost_explorer",
    "check_dynamodb_tables",
    "check_github_token",
    "check_kb_index",
    "check_langsmith_key",
    "check_security_trial",
    "check_slack_auth",
    "check_ssm_parameters",
    "check_state_machine_and_schedule",
    "check_sts_identity",
    "check_titan_access",
]
