"""Central boto3 client factory.

Convention: all AWS calls go through this module (retry mode adaptive,
max 10 attempts). Every collector, handler, and integration gets its
boto3 clients from here — nothing constructs `boto3.client(...)` directly
anywhere else in `src/`.
"""

from __future__ import annotations

from functools import cache
from typing import Any

import boto3
from botocore.config import Config

_RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})


@cache
def get_client(service_name: str, *, region_name: str | None = None) -> Any:
    """Return a cached boto3 client with adaptive retries for ``service_name``.

    ``service_name`` is a plain ``str`` here (this factory is generic across
    every AWS service this repo uses), which doesn't match boto3-stubs'
    per-service ``Literal`` overloads of ``boto3.client`` — hence the
    targeted ignore, rather than losing type checking on every call site.
    """
    return boto3.client(service_name, region_name=region_name, config=_RETRY_CONFIG)  # type: ignore[call-overload]


def get_bedrock_runtime_client(*, region_name: str | None = None) -> Any:
    return get_client("bedrock-runtime", region_name=region_name)


def get_s3_client(*, region_name: str | None = None) -> Any:
    return get_client("s3", region_name=region_name)


def get_dynamodb_client(*, region_name: str | None = None) -> Any:
    return get_client("dynamodb", region_name=region_name)


def get_dynamodb_resource(*, region_name: str | None = None) -> Any:
    return boto3.resource("dynamodb", region_name=region_name, config=_RETRY_CONFIG)


def get_ssm_client(*, region_name: str | None = None) -> Any:
    return get_client("ssm", region_name=region_name)


def get_lambda_client(*, region_name: str | None = None) -> Any:
    return get_client("lambda", region_name=region_name)


def get_sts_client(*, region_name: str | None = None) -> Any:
    return get_client("sts", region_name=region_name)


def get_bedrock_client(*, region_name: str | None = None) -> Any:
    return get_client("bedrock", region_name=region_name)


def get_scheduler_client(*, region_name: str | None = None) -> Any:
    return get_client("scheduler", region_name=region_name)


def get_securityhub_client(*, region_name: str | None = None) -> Any:
    return get_client("securityhub", region_name=region_name)


def get_guardduty_client(*, region_name: str | None = None) -> Any:
    return get_client("guardduty", region_name=region_name)


def get_config_client(*, region_name: str | None = None) -> Any:
    return get_client("config", region_name=region_name)


def get_ce_client(*, region_name: str | None = None) -> Any:
    return get_client("ce", region_name=region_name)


def get_budgets_client() -> Any:
    """Budgets is a global service reachable only via the us-east-1 endpoint."""
    return get_client("budgets", region_name="us-east-1")


def assume_role_client(
    service_name: str,
    *,
    role_arn: str,
    session_name: str,
    tags: dict[str, str] | None = None,
    region_name: str | None = None,
) -> Any:
    """A boto3 client built from temporary ``sts:AssumeRole`` credentials --
    can't go through ``get_client``'s cache, since credentials are per-call
    (and expire), not a stable per-service singleton. Used by
    ``action_worker`` to assume the ``executor`` role, scoped per approved
    action via session tags, before dispatching a remediation."""
    sts = get_sts_client(region_name=region_name)
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        Tags=[{"Key": key, "Value": value} for key, value in (tags or {}).items()],
    )
    credentials = response["Credentials"]
    return boto3.client(  # type: ignore[call-overload]
        service_name,
        region_name=region_name,
        config=_RETRY_CONFIG,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


__all__ = [
    "assume_role_client",
    "get_bedrock_client",
    "get_bedrock_runtime_client",
    "get_budgets_client",
    "get_ce_client",
    "get_client",
    "get_config_client",
    "get_dynamodb_client",
    "get_dynamodb_resource",
    "get_guardduty_client",
    "get_lambda_client",
    "get_s3_client",
    "get_scheduler_client",
    "get_securityhub_client",
    "get_ssm_client",
    "get_sts_client",
]
