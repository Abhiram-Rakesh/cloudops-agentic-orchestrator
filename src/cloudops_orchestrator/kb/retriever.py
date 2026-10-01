"""Hybrid SOP retrieval: control-ID pass + BM25 + semantic, fused, with
cross-reference expansion.

Loads the built index once per process (Lambda container reuse across
invocations keeps this cheap) and caches retrieval results per
``group_id`` within that lifetime.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path
from typing import Any, Protocol

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.kb.bm25 import BM25Index
from cloudops_orchestrator.kb.embeddings import get_embedder
from cloudops_orchestrator.kb.local_paths import resolve_local_index_path
from cloudops_orchestrator.logging import get_logger
from cloudops_orchestrator.models.enums import KBDomain, Severity
from cloudops_orchestrator.models.findings import FindingGroup
from cloudops_orchestrator.models.sop import SOPChunk

logger = get_logger()

RRF_K = 60


class SOPRetriever(Protocol):
    def retrieve(self, group: FindingGroup, *, top_k: int = 5) -> list[SOPChunk]: ...


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _reciprocal_rank_fusion(rankings: list[list[str]], *, k: int = RRF_K) -> dict[str, float]:
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, key in enumerate(ranking, start=1):
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank)
    return scores


def _build_query_text(group: FindingGroup) -> str:
    sample = group.sample[0] if group.sample else None
    title = sample.title if sample else group.rule_id
    description = sample.description if sample else ""
    controls_str = ", ".join(group.control_ids) if group.control_ids else group.rule_id
    return (
        f"{group.domain.value} finding: {title}. Resource type: {group.resource_type}. "
        f"Controls: {controls_str}. {description[:200]}"
    )


def _load_index(path: Path) -> dict[str, Any]:
    raw = gzip.decompress(path.read_bytes())
    result: dict[str, Any] = json.loads(raw)
    return result


class HybridIndexRetriever:
    def __init__(self, settings: Settings, *, index_path: Path | None = None) -> None:
        self._settings = settings
        resolved_path = index_path or resolve_local_index_path(settings)
        data = _load_index(resolved_path)

        self._model_id: str = data["model_id"]
        self._dims: int = data["dims"]
        self._clause_map: dict[str, str] = data["clause_map"]
        self._chunks_by_key: dict[str, dict[str, Any]] = {c["key"]: c for c in data["chunks"]}
        self._vectors: dict[str, list[float]] = {
            c["key"]: c["vector"] for c in data["chunks"] if c["vector"] is not None
        }
        self._bm25 = BM25Index.from_dict(data["bm25"])
        self._cache: dict[str, list[SOPChunk]] = {}
        self._semantic_warned = False

        self._query_embeddings = settings.kb.query_embeddings
        self._min_score = settings.kb.min_score
        self._embedder = (
            get_embedder("titan", dimensions=self._dims)
            if self._query_embeddings == "titan"
            else None
        )

    def _eligible_keys(self, domain: str) -> list[str]:
        allowed = {domain, KBDomain.SHARED.value}
        return [
            key
            for key, chunk in self._chunks_by_key.items()
            if chunk["metadata"]["domain"] in allowed
        ]

    def _to_chunk(self, key: str, *, score: float, expanded: bool = False) -> SOPChunk:
        record = self._chunks_by_key[key]
        meta = record["metadata"]
        severity = Severity(meta["severity"]) if meta["severity"] else None
        return SOPChunk(
            key=key,
            sop_id=meta["sop_id"],
            clause_id=meta["clause_id"],
            domain=KBDomain(meta["domain"]),
            controls=meta["controls"],
            prowler_checks=meta["prowler_checks"],
            severity=severity,
            version=meta["version"],
            references=meta["references"],
            title=meta["title"],
            source_path=meta["source_path"],
            text=record["text"],
            score=score,
            expanded=expanded,
        )

    def _clause_id_of(self, key: str) -> str:
        meta = self._chunks_by_key[key]["metadata"]
        clause_id: str = meta["clause_id"] or meta["sop_id"]
        return clause_id

    def _semantic_pass(self, query_text: str, eligible_keys: list[str]) -> list[tuple[str, float]]:
        if self._embedder is None:
            return []
        try:
            query_vector = self._embedder.embed([query_text])[0]
        except Exception:
            if not self._semantic_warned:
                logger.warning("kb.retriever.semantic_pass_unavailable", model_id=self._model_id)
                self._semantic_warned = True
            return []
        scored = [
            (key, _cosine(query_vector, self._vectors[key]))
            for key in eligible_keys
            if key in self._vectors
        ]
        scored = [(key, score) for key, score in scored if score > 0]
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored

    def retrieve(self, group: FindingGroup, *, top_k: int = 5) -> list[SOPChunk]:
        if group.group_id in self._cache:
            return self._cache[group.group_id]

        eligible_keys = self._eligible_keys(group.domain.value)
        control_id_set = set(group.control_ids)

        control_hits = [
            key
            for key in eligible_keys
            if control_id_set
            & (
                set(self._chunks_by_key[key]["metadata"]["controls"])
                | set(self._chunks_by_key[key]["metadata"]["prowler_checks"])
            )
        ]

        query_text = _build_query_text(group)
        bm25_pairs = self._bm25.search(query_text, keys=eligible_keys, top_k=top_k * 3)
        bm25_ranking = [key for key, _score in bm25_pairs]
        bm25_raw_scores = dict(bm25_pairs)

        semantic_pairs = self._semantic_pass(query_text, eligible_keys)
        semantic_ranking = [key for key, _score in semantic_pairs]
        semantic_scores = dict(semantic_pairs)

        # RRF combines the two rankings into an order. Its magnitude is rank-based (max ~1/(RRF_K+1)) and not a
        # meaningful scale for `kb.min_score`, so the *gate* below instead
        # uses a bounded relevance score per source: BM25's raw score run
        # through a saturating x/(x+1) map, and cosine similarity as-is.
        fused_scores = _reciprocal_rank_fusion([bm25_ranking, semantic_ranking])
        ordered = control_hits + sorted(fused_scores, key=lambda k: fused_scores[k], reverse=True)

        def _relevance(key: str) -> float:
            bm25_raw = bm25_raw_scores.get(key, 0.0)
            bm25_norm = bm25_raw / (bm25_raw + 1.0) if bm25_raw > 0 else 0.0
            return max(bm25_norm, semantic_scores.get(key, 0.0))

        results: list[SOPChunk] = []
        seen_clauses: set[str] = set()
        for key in ordered:
            clause_id = self._clause_id_of(key)
            if clause_id in seen_clauses:
                continue
            score = 1.0 if key in control_hits else _relevance(key)
            if key not in control_hits and score < self._min_score:
                continue
            seen_clauses.add(clause_id)
            results.append(self._to_chunk(key, score=score))
            if len(results) >= top_k:
                break

        results.extend(self._expand_references(results[:3], seen_clauses))
        self._cache[group.group_id] = results
        return results

    def _expand_references(
        self, top_results: list[SOPChunk], seen_clauses: set[str]
    ) -> list[SOPChunk]:
        expanded: list[SOPChunk] = []
        for result in top_results:
            for ref in result.references:
                if len(expanded) >= 3:
                    return expanded
                target_key = self._clause_map.get(ref)
                if target_key is None:
                    continue
                clause_id = self._clause_id_of(target_key)
                if clause_id in seen_clauses:
                    continue
                seen_clauses.add(clause_id)
                expanded.append(self._to_chunk(target_key, score=0.0, expanded=True))
        return expanded

    def query_raw(self, text: str, *, domain: str | None = None, top_k: int = 5) -> list[SOPChunk]:
        """Ad-hoc text query (no control-ID pass) — used by `cloudops kb query` for debugging."""
        eligible_keys = self._eligible_keys(domain) if domain else list(self._chunks_by_key)
        bm25_ranking = [
            key for key, _score in self._bm25.search(text, keys=eligible_keys, top_k=top_k * 3)
        ]
        semantic_ranking = [key for key, _score in self._semantic_pass(text, eligible_keys)]
        fused_scores = _reciprocal_rank_fusion([bm25_ranking, semantic_ranking])
        ordered = sorted(fused_scores, key=lambda k: fused_scores[k], reverse=True)
        return [self._to_chunk(key, score=fused_scores[key]) for key in ordered[:top_k]]


def query_index(settings: Settings, *, text: str, domain: str | None = None) -> list[SOPChunk]:
    retriever = HybridIndexRetriever(settings)
    return retriever.query_raw(text, domain=domain)


__all__ = ["HybridIndexRetriever", "SOPRetriever", "query_index"]
