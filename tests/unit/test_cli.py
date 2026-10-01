from __future__ import annotations

from moto import mock_aws
from typer.testing import CliRunner

from cloudops_orchestrator import __version__
from cloudops_orchestrator.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "CloudOps Agentic Orchestrator" in result.stdout


def test_trials_status_degrades_gracefully_when_ssm_parameter_is_missing() -> None:
    # mock_aws intercepts every boto3 call for the duration of the context,
    # so this never reaches a real AWS account even if one is configured on
    # the machine running the test (~/.aws/credentials) -- see
    # tests/unit/test_doctor.py for the same pattern.
    with mock_aws():
        result = runner.invoke(app, ["trials", "status", "--config", "config/settings.local.yaml"])
    assert result.exit_code == 0, result.output
    assert "Phase:" in result.output
    assert "Could not read trial_start_date" in result.output
