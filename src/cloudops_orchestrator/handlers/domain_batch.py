"""``domain_batch`` Lambda: runs the domain agent graph for one
batch and writes its ``DomainBatchResult`` to S3, returning only
``{batch_id, status, cost_usd}``.

Real AWS/Anthropic wiring only; not exercised by tests — ``graph/domain_agent.py``
and ``steps/run_domain_batch.py`` carry the tested logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.aws.clients import get_s3_client, get_ssm_client
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.graph.domain_agent import DomainAgentDeps
    from cloudops_orchestrator.kb.index_builder import build_index
    from cloudops_orchestrator.kb.parser import clause_text_index
    from cloudops_orchestrator.kb.retriever import HybridIndexRetriever
    from cloudops_orchestrator.llm.budget import BudgetTracker
    from cloudops_orchestrator.llm.factory import get_reasoning_model, get_triage_model
    from cloudops_orchestrator.llm.tracing import enable_tracing, flush_tracing
    from cloudops_orchestrator.models.enums import Domain
    from cloudops_orchestrator.policy.config import (
        load_action_allowlist,
        load_protected_resources,
        load_risk_tiers,
    )
    from cloudops_orchestrator.steps.plan_batches import plan_batches
    from cloudops_orchestrator.steps.run_domain_batch import run_domain_batch
    from cloudops_orchestrator.steps.serialization import (
        deserialize_findings,
        deserialize_groups,
        deserialize_masker,
        serialize_domain_result,
    )

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    run_id = event["run_id"]
    domain = Domain(event["domain"])
    batch_id = event["batch_id"]

    s3 = get_s3_client(region_name=settings.aws.region)
    bucket = settings.storage.bucket
    ssm = get_ssm_client(region_name=settings.aws.region)
    anthropic_api_key = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/anthropic_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    langsmith_api_key = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/langsmith_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    enable_tracing(settings.langsmith, api_key=langsmith_api_key)
    groups = deserialize_groups(
        s3.get_object(Bucket=bucket, Key=f"runs/{run_id}/groups/{domain.value}.json")["Body"]
        .read()
        .decode("utf-8")
    )
    findings = deserialize_findings(
        s3.get_object(Bucket=bucket, Key=f"runs/{run_id}/findings.json")["Body"]
        .read()
        .decode("utf-8")
    )
    findings_by_fingerprint = {f.fingerprint: f for f in findings}
    masker = deserialize_masker(
        s3.get_object(Bucket=bucket, Key=f"runs/{run_id}/masker.json")["Body"]
        .read()
        .decode("utf-8")
    )

    batches = plan_batches(
        {domain: groups}, max_groups_per_batch=settings.orchestration.max_groups_per_batch
    )
    batch = next(b for b in batches if b.batch_id == batch_id)

    kb_dir = Path("knowledge_base")
    embeddings = "none" if settings.kb.query_embeddings == "none" else "titan"
    build_index(settings, embeddings=embeddings, upload=False, kb_dir=kb_dir)
    retriever = HybridIndexRetriever(settings)

    deps = DomainAgentDeps(
        run_id=run_id,
        settings=settings,
        retriever=retriever,
        triage_model=get_triage_model(settings.llm, api_key=anthropic_api_key),
        reasoning_model=get_reasoning_model(settings.llm, api_key=anthropic_api_key),
        budget=BudgetTracker(
            config=settings.llm, max_cost_usd_per_run=settings.llm.max_cost_usd_per_run
        ),
        clause_texts=clause_text_index(kb_dir),
        risk_tiers=load_risk_tiers(),
        action_allowlist=load_action_allowlist(),
        protected_resources=load_protected_resources(),
        findings_by_fingerprint=findings_by_fingerprint,
        masker=masker,
    )
    result = run_domain_batch(batch, deps=deps)

    s3.put_object(
        Bucket=bucket,
        Key=f"runs/{run_id}/results/{domain.value}/{batch_id}.json",
        Body=serialize_domain_result(result).encode("utf-8"),
        ContentType="application/json",
    )
    flush_tracing()
    return {"batch_id": batch_id, "status": "ok", "cost_usd": result.cost_usd}


__all__ = ["lambda_handler"]
