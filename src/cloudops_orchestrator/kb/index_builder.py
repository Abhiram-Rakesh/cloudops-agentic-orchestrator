"""Build ``sop_index.json.gz``: the SOP knowledge base's embeddings + BM25 index.

Pipeline:
1. Parse + validate every SOP into chunks (`kb/parser.py`, `kb/chunker.py`).
2. Embed each chunk with Titan (skipped for ``embeddings="none"``, which
   yields a BM25-only index), reusing the previous index's vector for any
   chunk whose content hash is unchanged.
3. Build BM25 statistics over the same chunk texts.
4. Write ``{kb_version, model_id, dims, chunks, bm25, clause_map}`` gzipped,
   locally and (optionally) to S3 at both the ``latest`` and versioned keys.
"""

from __future__ import annotations

import gzip
import json
import subprocess
from pathlib import Path
from typing import Any

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.kb.bm25 import BM25Index
from cloudops_orchestrator.kb.chunker import chunk_documents
from cloudops_orchestrator.kb.embeddings import content_sha256, get_embedder
from cloudops_orchestrator.kb.local_paths import resolve_local_index_path
from cloudops_orchestrator.kb.parser import parse_knowledge_base, validate_knowledge_base
from cloudops_orchestrator.logging import get_logger

logger = get_logger()


def _get_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return "unknown"


def _load_previous_vectors(path: Path) -> dict[str, list[float] | None]:
    if not path.exists():
        return {}
    try:
        raw = gzip.decompress(path.read_bytes())
        data = json.loads(raw)
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError):
        return {}
    return {chunk["content_sha256"]: chunk["vector"] for chunk in data.get("chunks", [])}


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    without_scheme = uri.removeprefix("s3://")
    bucket, _, key = without_scheme.partition("/")
    return bucket, key


def _upload_to_s3(settings: Settings, local_path: Path, kb_version: str) -> None:
    from cloudops_orchestrator.aws.clients import get_s3_client

    bucket, latest_key = _parse_s3_uri(settings.kb.index_uri)
    versioned_key = str(Path(latest_key).parent / f"{kb_version}.json.gz")

    body = local_path.read_bytes()
    client = get_s3_client(region_name=settings.aws.region)
    client.put_object(Bucket=bucket, Key=latest_key, Body=body, ContentType="application/gzip")
    client.put_object(Bucket=bucket, Key=versioned_key, Body=body, ContentType="application/gzip")
    logger.info(
        "kb.index.uploaded", bucket=bucket, latest_key=latest_key, versioned_key=versioned_key
    )


def build_index(
    settings: Settings,
    *,
    embeddings: str,
    upload: bool = False,
    kb_dir: Path = Path("knowledge_base"),
) -> Path:
    errors = validate_knowledge_base(kb_dir)
    if errors:
        msg = "Knowledge base failed validation:\n" + "\n".join(errors)
        raise ValueError(msg)

    documents = parse_knowledge_base(kb_dir)
    chunks = chunk_documents(documents)
    embedder = (
        None
        if embeddings == "none"
        else get_embedder(embeddings, dimensions=settings.kb.embedding_dimensions)
    )

    output_path = resolve_local_index_path(settings)
    previous_vectors = _load_previous_vectors(output_path)

    hashes = [content_sha256(chunk.text) for chunk in chunks]
    vectors: list[list[float] | None] = [
        previous_vectors.get(h) if embedder else None for h in hashes
    ]

    missing_indices = [i for i, v in enumerate(vectors) if v is None] if embedder else []
    if embedder is not None and missing_indices:
        missing_texts = [chunks[i].text for i in missing_indices]
        computed = embedder.embed(missing_texts)
        for i, vector in zip(missing_indices, computed, strict=True):
            vectors[i] = vector

    bm25 = BM25Index.build({chunk.key: chunk.text for chunk in chunks})
    kb_version = _get_git_sha()

    chunk_records: list[dict[str, Any]] = []
    clause_map: dict[str, str] = {}
    for chunk, content_hash, stored_vector in zip(chunks, hashes, vectors, strict=True):
        chunk_records.append(
            {
                "key": chunk.key,
                "metadata": {
                    "domain": chunk.domain.value,
                    "sop_id": chunk.sop_id,
                    "clause_id": chunk.clause_id,
                    "controls": chunk.controls,
                    "prowler_checks": chunk.prowler_checks,
                    "severity": chunk.severity.value if chunk.severity else None,
                    "version": chunk.version,
                    "references": chunk.references,
                    "title": chunk.title,
                    "source_path": chunk.source_path,
                },
                "text": chunk.text,
                "vector": stored_vector,
                "content_sha256": content_hash,
            }
        )
        if chunk.clause_id:
            clause_map[chunk.clause_id] = chunk.key

    index_data = {
        "kb_version": kb_version,
        "model_id": embedder.model_id if embedder else "none",
        "dims": embedder.dimensions if embedder else settings.kb.embedding_dimensions,
        "chunks": chunk_records,
        "bm25": bm25.to_dict(),
        "clause_map": clause_map,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(gzip.compress(json.dumps(index_data).encode("utf-8")))
    logger.info(
        "kb.index.built",
        chunks=len(chunk_records),
        embedded=len(missing_indices),
        reused=sum(v is not None for v in vectors) - len(missing_indices),
        kb_version=kb_version,
        output_path=str(output_path),
    )

    if upload:
        _upload_to_s3(settings, output_path, kb_version)

    return output_path


__all__ = ["build_index"]
