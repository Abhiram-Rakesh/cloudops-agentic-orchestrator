"""`cloudops` CLI entry point (Typer).

Command groups: ``kb`` (knowledge base), ``exceptions``, ``trials``, plus
``run``, ``resume`` and ``doctor``. See the implementation module behind each
command for what backs it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from cloudops_orchestrator import __version__
from cloudops_orchestrator.config import ConfigError, Settings, load_settings

app = typer.Typer(
    name="cloudops",
    help="CloudOps Agentic Orchestrator CLI",
    no_args_is_help=True,
)
kb_app = typer.Typer(help="Knowledge base commands")
app.add_typer(kb_app, name="kb")

console = Console()


def _load_settings_or_exit(config: str) -> Settings:
    """Load settings, turning a missing-variable error into a short message."""
    try:
        return load_settings(config)
    except ConfigError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        console.print(
            "Export those variables in your shell, or put them in a [bold].env[/bold] file in "
            "the repo root (see .env.example)."
        )
        raise typer.Exit(code=1) from exc


@app.callback(invoke_without_command=False)
def _main() -> None:
    """CloudOps Agentic Orchestrator."""


@app.command()
def version() -> None:
    """Print the installed package version."""
    console.print(__version__)


@kb_app.command("build")
def kb_build(
    embeddings: Annotated[str, typer.Option(help="titan | none (BM25 only)")] = "none",
    upload: Annotated[bool, typer.Option(help="Upload the built index to S3")] = False,
    config: Annotated[str, typer.Option()] = "config/settings.local.yaml",
    kb_dir: Annotated[Path, typer.Option(help="Knowledge base directory")] = Path("knowledge_base"),
) -> None:
    """Build the SOP knowledge base index."""
    from cloudops_orchestrator.kb.index_builder import build_index

    settings = _load_settings_or_exit(config)
    output_path = build_index(settings, embeddings=embeddings, upload=upload, kb_dir=kb_dir)
    console.print(f"Wrote index to {output_path}")


@kb_app.command("validate")
def kb_validate(
    kb_dir: Annotated[Path, typer.Option(help="Knowledge base directory")] = Path("knowledge_base"),
) -> None:
    """Validate every SOP's front-matter and clause-meta schema."""
    from cloudops_orchestrator.kb.parser import validate_knowledge_base

    errors = validate_knowledge_base(kb_dir)
    if errors:
        for error in errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1)
    console.print("[green]Knowledge base is valid.[/green]")


@kb_app.command("query")
def kb_query(
    text: str,
    domain: Annotated[str | None, typer.Option()] = None,
    config: Annotated[str, typer.Option()] = "config/settings.local.yaml",
) -> None:
    """Query the built index (debugging aid for retrieval tuning)."""
    from cloudops_orchestrator.kb.retriever import query_index

    settings = _load_settings_or_exit(config)
    for chunk in query_index(settings, text=text, domain=domain):
        console.print(f"{chunk.clause_id or chunk.sop_id} (score={chunk.score:.3f}): {chunk.title}")


exceptions_app = typer.Typer(help="SOP exception commands (SHARED-003)")
app.add_typer(exceptions_app, name="exceptions")

trials_app = typer.Typer(help="Security-services trial lifecycle commands")
app.add_typer(trials_app, name="trials")


@trials_app.command("status")
def trials_status(
    config: Annotated[str, typer.Option()] = "config/settings.dev.yaml",
) -> None:
    """Show the current security-services trial phase, days remaining, and
    next steps (see README.md (Security trial lifecycle))."""
    from datetime import UTC, datetime

    settings = _load_settings_or_exit(config)
    in_trial = settings.collectors.security_hub.enabled
    phase = (
        "A -- trial (Security Hub + GuardDuty + Config + Prowler, in parallel)"
        if in_trial
        else "B -- post-switchover (Prowler + IAM Access Analyzer only)"
    )
    console.print(f"Phase: {phase}")

    from cloudops_orchestrator.aws.clients import get_ssm_client

    prefix = settings.storage.parameter_prefix
    try:
        ssm = get_ssm_client(region_name=settings.aws.region)
        trial_start_date = ssm.get_parameter(Name=f"{prefix}/trial_start_date")["Parameter"][
            "Value"
        ]
        started = datetime.fromisoformat(f"{trial_start_date}T00:00:00+00:00")
        days_elapsed = (datetime.now(UTC) - started).days
        days_remaining = 30 - days_elapsed
        console.print(
            f"Trial started: {trial_start_date} (day {days_elapsed}, "
            f"{days_remaining} day(s) until the 30-day trial window ends)"
        )
        if in_trial and days_remaining <= 5:
            console.print(
                "[yellow]Switchover is due soon -- see README.md (Security trial lifecycle) "
                "and run `make trials-off`.[/yellow]"
            )
    except Exception as exc:
        console.print(
            f"[dim]Could not read trial_start_date from SSM ({exc}) -- "
            "not deployed yet, or check AWS credentials.[/dim]"
        )

    if in_trial:
        console.print(
            "Next steps: `make seed-guardduty` for demo GuardDuty findings; "
            "a one-time day-25 reminder fires automatically; switch over with "
            "`make trials-off` when it does."
        )
    else:
        console.print(
            "Next steps: none -- already in Phase B. GuardDuty/Config "
            "threat-response clauses (SEC-004-4.2, SEC-005-5.4) are now "
            "exercised through fixtures only."
        )


@exceptions_app.command("list")
def exceptions_list(config: Annotated[str, typer.Option()] = "config/settings.dev.yaml") -> None:
    """List active SOP exceptions."""
    from cloudops_orchestrator.store.exceptions import list_exceptions

    settings = _load_settings_or_exit(config)
    exceptions = list_exceptions(settings)
    if not exceptions:
        console.print("No exceptions on file.")
        return
    for exception in exceptions:
        console.print(
            f"{exception.exception_id}  {exception.clause_id}  expires={exception.expires_at.date()}  "
            f"control={exception.compensating_control}"
        )


@exceptions_app.command("add")
def exceptions_add(
    clause: Annotated[str, typer.Option(help="Clause ID, e.g. SEC-004-4.2")],
    days: Annotated[int, typer.Option(help="Exception duration in days")],
    compensating_control: Annotated[str, typer.Option()],
    fingerprint: Annotated[str | None, typer.Option()] = None,
    owner: Annotated[str | None, typer.Option()] = None,
    justification: Annotated[str, typer.Option()] = "",
    config: Annotated[str, typer.Option()] = "config/settings.dev.yaml",
) -> None:
    """Record a time-bound SOP exception (SHARED-003)."""
    from cloudops_orchestrator.store.exceptions import add_exception

    settings = _load_settings_or_exit(config)
    exception = add_exception(
        settings,
        clause_id=clause,
        duration_days=days,
        compensating_control=compensating_control,
        justification=justification,
        fingerprint=fingerprint,
        owner=owner,
    )
    console.print(
        f"Recorded exception {exception.exception_id} expiring {exception.expires_at.date()}"
    )


@exceptions_app.command("remove")
def exceptions_remove(
    exception_id: Annotated[str, typer.Option()],
    config: Annotated[str, typer.Option()] = "config/settings.dev.yaml",
) -> None:
    """Remove a SOP exception early."""
    from cloudops_orchestrator.store.exceptions import remove_exception

    settings = _load_settings_or_exit(config)
    remove_exception(settings, exception_id=exception_id)
    console.print(f"Removed exception {exception_id}")


@app.command()
def doctor(
    config: Annotated[str, typer.Option()] = "config/settings.dev.yaml",
) -> None:
    """Read-only health checks against a real deployed account.
    Never mutates anything; every check degrades to WARN/SKIP rather than
    crashing the whole command."""

    from urllib.parse import urlparse

    from cloudops_orchestrator import doctor as doctor_checks
    from cloudops_orchestrator.aws.clients import (
        get_bedrock_client,
        get_budgets_client,
        get_ce_client,
        get_config_client,
        get_dynamodb_client,
        get_guardduty_client,
        get_s3_client,
        get_scheduler_client,
        get_securityhub_client,
        get_ssm_client,
        get_sts_client,
    )
    from cloudops_orchestrator.integrations.github_client import GithubClient

    settings = _load_settings_or_exit(config)
    region = settings.aws.region
    prefix = settings.storage.parameter_prefix
    sts = get_sts_client(region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    ssm = get_ssm_client(region_name=region)
    parsed_index_uri = urlparse(settings.kb.index_uri)

    checks: list[doctor_checks.DoctorCheck] = [
        doctor_checks.check_sts_identity(sts),
        doctor_checks.check_dynamodb_tables(
            get_dynamodb_client(region_name=region),
            [settings.storage.state_table, settings.storage.checkpoint_table],
        ),
        doctor_checks.check_ssm_parameters(
            ssm,
            [
                f"{prefix}/anthropic_api_key",  # gitleaks:allow
                f"{prefix}/langsmith_api_key",  # gitleaks:allow
                f"{prefix}/slack_bot_token",  # gitleaks:allow
                f"{prefix}/slack_signing_secret",  # gitleaks:allow
                f"{prefix}/github_token",  # gitleaks:allow
            ],
        ),
        doctor_checks.check_titan_access(get_bedrock_client(region_name=region)),
        doctor_checks.check_security_trial(
            securityhub_client=get_securityhub_client(region_name=region),
            guardduty_client=get_guardduty_client(region_name=region),
            config_client=get_config_client(region_name=region),
            trial_start_date=ssm.get_parameter(Name=f"{prefix}/trial_start_date")["Parameter"][
                "Value"
            ],
        ),
        doctor_checks.check_cost_explorer(get_ce_client(region_name=region)),
        doctor_checks.check_kb_index(
            get_s3_client(region_name=region),
            bucket=parsed_index_uri.netloc,
            key=parsed_index_uri.path.lstrip("/"),
        ),
        doctor_checks.check_artifact_freshness(
            get_s3_client(region_name=region),
            bucket=settings.storage.bucket,
            key=f"{settings.collectors.prowler.prefix}findings.json",
            max_age_days=settings.collectors.prowler.max_age_days,
        ),
        doctor_checks.check_artifact_freshness(
            get_s3_client(region_name=region),
            bucket=settings.storage.bucket,
            key=f"{settings.collectors.drift.prefix}orders-demo/plan.json",
            max_age_days=settings.collectors.drift.max_age_days,
        ),
        doctor_checks.check_langsmith_key(
            ssm,
            parameter_name=f"{prefix}/langsmith_api_key",  # gitleaks:allow
        ),
        doctor_checks.check_state_machine_and_schedule(
            get_scheduler_client(region_name=region),
            name_prefix=settings.storage.bucket.rsplit("-", 1)[0],
        ),
        doctor_checks.check_budgets(get_budgets_client(), account_id=account_id),
    ]

    try:
        github_token = ssm.get_parameter(
            Name=f"{prefix}/github_token",  # gitleaks:allow
            WithDecryption=True,
        )["Parameter"]["Value"]
        github_client = GithubClient(
            token=github_token, owner=settings.github.owner, repo=settings.github.repo
        )
        checks.append(
            doctor_checks.check_github_token(
                github_client, owner=settings.github.owner, repo=settings.github.repo
            )
        )
    except Exception as exc:
        checks.append(
            doctor_checks.DoctorCheck("github_token", doctor_checks.CheckStatus.FAIL, str(exc))
        )

    try:
        from slack_sdk import WebClient

        slack_token = ssm.get_parameter(
            Name=f"{prefix}/slack_bot_token",  # gitleaks:allow
            WithDecryption=True,
        )["Parameter"]["Value"]
        checks.append(doctor_checks.check_slack_auth(WebClient(token=slack_token)))
    except Exception as exc:
        checks.append(
            doctor_checks.DoctorCheck("slack_auth", doctor_checks.CheckStatus.FAIL, str(exc))
        )

    status_colors = {
        doctor_checks.CheckStatus.OK: "green",
        doctor_checks.CheckStatus.WARN: "yellow",
        doctor_checks.CheckStatus.SKIP: "dim",
        doctor_checks.CheckStatus.FAIL: "red",
    }
    for check in checks:
        color = status_colors[check.status]
        console.print(f"[{color}]{check.status.value:5}[/{color}] {check.name}: {check.detail}")

    if any(c.status == doctor_checks.CheckStatus.FAIL for c in checks):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
