"""Embedding backends for the SOP knowledge base index.

``TitanEmbedder`` calls Bedrock's ``amazon.titan-embed-text-v2:0`` model
(one ``invoke_model`` call per text — Titan V2 does not batch). Its
availability in the target region is *not* verified against a live account
in this build (Hard Rule #2/#5) — see `README.md (Troubleshooting)`.
`--embeddings none` builds a BM25-only index (no vectors, no Bedrock call);
see ``kb.query_embeddings`` in the settings.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol


class Embedder(Protocol):
    model_id: str
    dimensions: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class TitanEmbedder:
    """Bedrock Titan Text Embeddings V2, called one text at a time."""

    model_id = "amazon.titan-embed-text-v2:0"

    def __init__(self, dimensions: int = 1024, client: Any = None) -> None:
        self.dimensions = dimensions
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            from cloudops_orchestrator.aws.clients import get_bedrock_runtime_client

            self._client = get_bedrock_runtime_client()
        return self._client

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        body = json.dumps({"inputText": text, "dimensions": self.dimensions, "normalize": True})
        response = self.client.invoke_model(
            modelId=self.model_id,
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        payload = json.loads(response["body"].read())
        embedding: list[float] = payload["embedding"]
        return [round(v, 6) for v in embedding]


def get_embedder(name: str, *, dimensions: int = 1024) -> Embedder:
    if name == "titan":
        return TitanEmbedder(dimensions=dimensions)
    msg = f"Unknown embedder {name!r}, expected 'titan'"
    raise ValueError(msg)


def content_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = ["Embedder", "TitanEmbedder", "content_sha256", "get_embedder"]
