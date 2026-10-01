from __future__ import annotations

import re

import pytest

from cloudops_orchestrator.normalize.masking import Masker


def test_masks_account_id() -> None:
    masker = Masker()
    masked = masker.mask("account 111111111111 is affected")
    assert "111111111111" not in masked
    assert "ACCT_1" in masked
    assert masker.unmask(masked) == "account 111111111111 is affected"


def test_masks_arn_keeps_service_and_resource_type() -> None:
    masker = Masker()
    arn = "arn:aws:ec2:ap-south-1:111111111111:security-group/sg-0123456789abcdef0"
    masked = masker.mask(f"finding on {arn}")
    assert arn not in masked
    assert "111111111111" not in masked
    assert "sg-0123456789abcdef0" not in masked
    assert "ec2:security-group" in masked
    assert masker.unmask(masked) == f"finding on {arn}"


def test_masks_resource_id_with_type() -> None:
    masker = Masker()
    masked = masker.mask("security group sg-0123456789abcdef0 allows ingress")
    assert "sg-0123456789abcdef0" not in masked
    assert "security-group" in masked
    assert masker.unmask(masked) == "security group sg-0123456789abcdef0 allows ingress"


def test_masks_email() -> None:
    masker = Masker()
    masked = masker.mask("owned by alice@example.com")
    assert "alice@example.com" not in masked
    assert "EMAIL_1" in masked
    assert masker.unmask(masked) == "owned by alice@example.com"


def test_masks_ipv4() -> None:
    masker = Masker()
    masked = masker.mask("connection from 198.51.100.23 observed")
    assert "198.51.100.23" not in masked
    assert masker.unmask(masked) == "connection from 198.51.100.23 observed"


def test_preserves_world_open_cidrs_literally() -> None:
    masker = Masker()
    masked = masker.mask("ingress from 0.0.0.0/0 and ::/0 to port 22")
    assert "0.0.0.0/0" in masked
    assert "::/0" in masked
    # No tokens were minted for these — they are semantically important, not identifiers.
    assert "IP_" not in masked


def test_reuses_same_token_for_repeated_value() -> None:
    masker = Masker()
    masked = masker.mask("111111111111 and again 111111111111")
    tokens = re.findall(r"ACCT_\d+", masked)
    assert len(set(tokens)) == 1


def test_distinct_values_get_distinct_tokens() -> None:
    masker = Masker()
    masked = masker.mask("111111111111 and 222222222222")
    assert "ACCT_1" in masked
    assert "ACCT_2" in masked


def test_reverse_map_round_trips_across_a_new_instance() -> None:
    # The real-world shape of the bug this guards against: one Masker masks
    # findings during collection; a SEPARATE instance (reconstructed from
    # its reverse_map(), e.g. after an S3 round trip between two Lambda
    # invocations) must still be able to unmask whatever the first one
    # produced.
    first = Masker()
    masked = first.mask("account 111111111111, sg-0123456789abcdef0")

    second = Masker(reverse=first.reverse_map())
    assert second.unmask(masked) == "account 111111111111, sg-0123456789abcdef0"


def test_unmask_handles_model_dropping_the_type_suffix() -> None:
    # Confirmed live against a real Anthropic call: given a resource_id
    # masked as "RID_2(instance)", the model sometimes echoes back only
    # "RID_2" as a structured parameter value, reading "(instance)" as a
    # type annotation rather than part of the identifier itself.
    masker = Masker()
    masked = masker.mask("security group sg-0123456789abcdef0 allows ingress")
    assert "sg-0123456789abcdef0" not in masked
    bare_token = masker.reverse_map()
    (full_token,) = [t for t in bare_token if "(security-group)" in t]
    stripped = full_token.split("(")[0]
    assert masker.unmask(stripped) == "sg-0123456789abcdef0"


def test_fresh_masker_cannot_unmask_another_instances_tokens() -> None:
    first = Masker()
    masked = first.mask("account 111111111111")

    unrelated = Masker()
    assert unrelated.unmask(masked) == masked  # no-op: nothing to reverse


@pytest.mark.parametrize(
    "text",
    [
        "Security group sg-0a1b2c3d4e5f allows ingress from 0.0.0.0/0 on port 22, "
        "reported for account 111111111111 (arn:aws:ec2:ap-south-1:111111111111:security-group/sg-0a1b2c3d4e5f), "
        "owner alice@example.com, source IP 203.0.113.5.",
        "No identifiers here at all, just plain prose about a policy.",
        "Multiple accounts: 111111111111, 222222222222, 111111111111 again.",
    ],
)
def test_round_trip_property(text: str) -> None:
    masker = Masker()
    masked = masker.mask(text)
    assert masker.unmask(masked) == text
