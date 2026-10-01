from __future__ import annotations

from moto import mock_aws

from cloudops_orchestrator.aws.clients import (
    get_client,
    get_dynamodb_client,
    get_dynamodb_resource,
    get_s3_client,
    get_ssm_client,
)


@mock_aws
def test_get_client_uses_adaptive_retry_config() -> None:
    client = get_client("s3", region_name="ap-south-1")
    assert client.meta.config.retries["mode"] == "adaptive"
    # botocore normalizes max_attempts=10 into total_max_attempts=11
    # (1 initial attempt + 10 retries) — see Config(retries=...) docs.
    assert client.meta.config.retries["total_max_attempts"] == 11


@mock_aws
def test_get_client_is_cached_per_service_and_region() -> None:
    first = get_client("s3", region_name="ap-south-1")
    second = get_client("s3", region_name="ap-south-1")
    third = get_client("s3", region_name="us-east-1")
    assert first is second
    assert first is not third


@mock_aws
def test_service_specific_helpers_return_working_clients() -> None:
    s3 = get_s3_client(region_name="ap-south-1")
    s3.create_bucket(
        Bucket="cloudops-lite-test",
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )
    assert "cloudops-lite-test" in [b["Name"] for b in s3.list_buckets()["Buckets"]]

    ddb = get_dynamodb_client(region_name="ap-south-1")
    assert ddb.list_tables()["TableNames"] == []

    ssm = get_ssm_client(region_name="ap-south-1")
    ssm.put_parameter(Name="/test/param", Value="x", Type="String")
    assert ssm.get_parameter(Name="/test/param")["Parameter"]["Value"] == "x"

    resource = get_dynamodb_resource(region_name="ap-south-1")
    assert list(resource.tables.all()) == []
