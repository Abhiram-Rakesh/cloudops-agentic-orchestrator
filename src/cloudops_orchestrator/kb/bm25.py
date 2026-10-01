"""Pure-Python Okapi BM25 over the knowledge base, with an ID-preserving tokenizer.

The tokenizer keeps identifiers like ``EC2.13`` and ``SEC-002-2.1`` intact
as single tokens (internal ``.``/``-``/``_`` do not split a token) so a
query mentioning a control ID matches the clause that cites it, rather than
being shredded into meaningless numeric fragments.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*")

K1 = 1.5
B = 0.75

# Standard English stopwords plus this system's own retrieval-query
# scaffolding ("finding", "resource", "type", "controls" — every generated
# query text contains these verbatim, so they carry no discriminative signal and would otherwise let
# BM25 return a nonzero score for almost any query regardless of relevance).
STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "is",
        "are",
        "be",
        "must",
        "should",
        "not",
        "no",
        "any",
        "all",
        "every",
        "with",
        "by",
        "as",
        "it",
        "this",
        "that",
        "at",
        "from",
        "per",
        "than",
        "then",
        "such",
        "into",
        "via",
        "finding",
        "resource",
        "type",
        "controls",
        "control",
    }
)


def tokenize(text: str) -> list[str]:
    return [
        token for token in (t.lower() for t in _TOKEN_RE.findall(text)) if token not in STOPWORDS
    ]


@dataclass
class BM25Index:
    k1: float = K1
    b: float = B
    doc_freq: dict[str, int] = field(default_factory=dict)
    term_freq: dict[str, dict[str, int]] = field(default_factory=dict)
    doc_length: dict[str, int] = field(default_factory=dict)
    avg_doc_length: float = 0.0

    @property
    def n_docs(self) -> int:
        return len(self.doc_length)

    @classmethod
    def build(cls, documents: dict[str, str]) -> BM25Index:
        """``documents``: chunk key -> raw text (already includes the contextual header)."""
        index = cls()
        total_length = 0
        for key, text in documents.items():
            tokens = tokenize(text)
            index.doc_length[key] = len(tokens)
            total_length += len(tokens)
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            index.term_freq[key] = counts
            for token in counts:
                index.doc_freq[token] = index.doc_freq.get(token, 0) + 1
        index.avg_doc_length = total_length / len(documents) if documents else 0.0
        return index

    def _idf(self, token: str, *, doc_freq: int, n_docs: int) -> float:
        return math.log((n_docs - doc_freq + 0.5) / (doc_freq + 0.5) + 1)

    def score(self, query: str, key: str) -> float:
        """Score against the *global* corpus statistics (all indexed docs)."""
        return self._score_with_stats(
            query,
            key,
            doc_freq=self.doc_freq,
            n_docs=self.n_docs,
            avg_doc_length=self.avg_doc_length,
        )

    def _score_with_stats(
        self,
        query: str,
        key: str,
        *,
        doc_freq: dict[str, int],
        n_docs: int,
        avg_doc_length: float,
    ) -> float:
        if key not in self.term_freq:
            return 0.0
        query_tokens = tokenize(query)
        counts = self.term_freq[key]
        doc_len = self.doc_length[key]
        score = 0.0
        for token in query_tokens:
            freq = counts.get(token, 0)
            if freq == 0:
                continue
            idf = self._idf(token, doc_freq=doc_freq.get(token, 0), n_docs=n_docs)
            denominator = freq + self.k1 * (1 - self.b + self.b * doc_len / (avg_doc_length or 1))
            score += idf * (freq * (self.k1 + 1)) / denominator
        return score

    def search(
        self, query: str, *, keys: list[str] | None = None, top_k: int = 10
    ) -> list[tuple[str, float]]:
        """Search, optionally restricted to ``keys``.

        When ``keys`` is given, document frequency and average length are
        recomputed *within that subset* rather than reused from the full
        index — otherwise a term that is common within a domain-filtered
        subset (e.g. "cost" across every cost-domain clause) but rarer
        globally would keep an inflated IDF from the full corpus, instead of
        correctly being treated as near-universal (and so non-discriminative)
        within the subset actually being searched.
        """
        if keys is None:
            candidates = list(self.term_freq)
            scored = [(key, self.score(query, key)) for key in candidates]
        else:
            query_tokens = set(tokenize(query))
            local_n = len(keys)
            local_doc_freq = {
                token: sum(1 for key in keys if token in self.term_freq.get(key, {}))
                for token in query_tokens
            }
            local_avg_length = (
                sum(self.doc_length.get(key, 0) for key in keys) / local_n if local_n else 0.0
            )
            scored = [
                (
                    key,
                    self._score_with_stats(
                        query,
                        key,
                        doc_freq=local_doc_freq,
                        n_docs=local_n,
                        avg_doc_length=local_avg_length,
                    ),
                )
                for key in keys
            ]

        scored = [(key, score) for key, score in scored if score > 0]
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:top_k]

    def to_dict(self) -> dict[str, Any]:
        return {
            "k1": self.k1,
            "b": self.b,
            "doc_freq": self.doc_freq,
            "term_freq": self.term_freq,
            "doc_length": self.doc_length,
            "avg_doc_length": self.avg_doc_length,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BM25Index:
        return cls(
            k1=data["k1"],
            b=data["b"],
            doc_freq=data["doc_freq"],
            term_freq=data["term_freq"],
            doc_length=data["doc_length"],
            avg_doc_length=data["avg_doc_length"],
        )


__all__ = ["BM25Index", "tokenize"]
