"""Chunk parsed SOP documents into ``SOPChunk`` records for embedding/indexing.

One chunk per clause, plus one overview chunk per SOP (built from the prose
before the first clause heading — Purpose/Scope/RACI/Definitions). Clauses
longer than ``MAX_CHUNK_TOKENS`` are split by paragraph with a
``OVERLAP_TOKENS``-sized overlap between consecutive pieces. Every chunk's
embedded text starts with a contextual header.

Token counts here are a deterministic, dependency-free approximation
(whitespace word count) — good enough to bound prompt/embedding size; exact
LLM token accounting happens in ``llm/budget.py`` from the API's own
``usage_metadata``, never from this heuristic.
"""

from __future__ import annotations

from cloudops_orchestrator.kb.parser import Clause, SOPDocument
from cloudops_orchestrator.models.sop import SOPChunk

MAX_CHUNK_TOKENS = 1500
OVERLAP_TOKENS = 100


def _approx_tokens(text: str) -> int:
    return len(text.split())


def _contextual_header(
    *,
    sop_id: str,
    clause_id: str | None,
    sop_title: str,
    section_title: str,
    domain: str,
    controls: list[str],
    prowler_checks: list[str],
    severity: str | None,
) -> str:
    controls_str = ", ".join(controls) if controls else "none"
    prowler_str = ", ".join(prowler_checks) if prowler_checks else "none"
    severity_str = severity or "n/a"
    location = f"{sop_id} {clause_id}" if clause_id else sop_id
    return (
        f"[{location} | {sop_title} > {section_title} | domain: {domain} | "
        f"controls: {controls_str} | prowler: {prowler_str} | severity: {severity_str}]"
    )


def _split_long_text(text: str, *, max_tokens: int, overlap_tokens: int) -> list[str]:
    paragraphs = [p for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        return [text]

    pieces: list[str] = []
    current: list[str] = []
    current_len = 0

    for paragraph in paragraphs:
        paragraph_len = _approx_tokens(paragraph)
        if current and current_len + paragraph_len > max_tokens:
            pieces.append("\n\n".join(current))
            joined_words = "\n\n".join(current).split()
            overlap_words = joined_words[-overlap_tokens:] if overlap_tokens else []
            current = [" ".join(overlap_words)] if overlap_words else []
            current_len = len(overlap_words)
        current.append(paragraph)
        current_len += paragraph_len

    if current:
        pieces.append("\n\n".join(current))
    return pieces


def _chunk_clause(doc: SOPDocument, clause: Clause) -> list[SOPChunk]:
    pieces = _split_long_text(
        clause.body, max_tokens=MAX_CHUNK_TOKENS, overlap_tokens=OVERLAP_TOKENS
    )
    chunks: list[SOPChunk] = []
    for index, piece in enumerate(pieces):
        key = clause.clause_id if len(pieces) == 1 else f"{clause.clause_id}#p{index}"
        header = _contextual_header(
            sop_id=doc.front_matter.sop_id,
            clause_id=clause.clause_id,
            sop_title=doc.front_matter.title,
            section_title=clause.title,
            domain=doc.front_matter.domain.value,
            controls=clause.meta.controls,
            prowler_checks=clause.meta.prowler_checks,
            severity=clause.meta.severity.value if clause.meta.severity else None,
        )
        chunks.append(
            SOPChunk(
                key=key,
                sop_id=doc.front_matter.sop_id,
                clause_id=clause.clause_id,
                domain=doc.front_matter.domain,
                controls=clause.meta.controls,
                prowler_checks=clause.meta.prowler_checks,
                severity=clause.meta.severity,
                version=doc.front_matter.version,
                references=clause.meta.references,
                title=clause.title,
                source_path=doc.source_path,
                text=f"{header}\n{piece}",
            )
        )
    return chunks


def _chunk_overview(doc: SOPDocument) -> SOPChunk:
    key = f"{doc.front_matter.sop_id}:overview"
    header = _contextual_header(
        sop_id=doc.front_matter.sop_id,
        clause_id=None,
        sop_title=doc.front_matter.title,
        section_title="Overview",
        domain=doc.front_matter.domain.value,
        controls=[],
        prowler_checks=[],
        severity=None,
    )
    return SOPChunk(
        key=key,
        sop_id=doc.front_matter.sop_id,
        clause_id=None,
        domain=doc.front_matter.domain,
        controls=[],
        prowler_checks=[],
        severity=None,
        version=doc.front_matter.version,
        references=doc.front_matter.references,
        title=doc.front_matter.title,
        source_path=doc.source_path,
        text=f"{header}\n{doc.overview_text}",
    )


def chunk_document(doc: SOPDocument) -> list[SOPChunk]:
    chunks = [_chunk_overview(doc)]
    for clause in doc.clauses:
        chunks.extend(_chunk_clause(doc, clause))
    return chunks


def chunk_documents(documents: list[SOPDocument]) -> list[SOPChunk]:
    chunks: list[SOPChunk] = []
    for doc in documents:
        chunks.extend(chunk_document(doc))
    return chunks


__all__ = ["MAX_CHUNK_TOKENS", "OVERLAP_TOKENS", "chunk_document", "chunk_documents"]
