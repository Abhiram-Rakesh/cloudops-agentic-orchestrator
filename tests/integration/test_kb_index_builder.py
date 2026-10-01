"""Integration tests for kb/index_builder.py: builds a real gzip+JSON index
from the real knowledge base in BM25-only mode (``embeddings="none"``).
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.kb.index_builder import build_index

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_DIR = REPO_ROOT / "knowledge_base"


def _local_settings_with_index_at(tmp_path: Path) -> object:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    index_path = tmp_path / "sop_index.json.gz"
    new_kb = settings.kb.model_copy(update={"index_uri": str(index_path)})
    return settings.model_copy(update={"kb": new_kb})


def test_build_index_produces_valid_gzip_json(tmp_path: Path) -> None:
    settings = _local_settings_with_index_at(tmp_path)
    output_path = build_index(settings, embeddings="none", upload=False, kb_dir=KB_DIR)

    assert output_path.exists()
    data = json.loads(gzip.decompress(output_path.read_bytes()))
    assert data["model_id"] == "none"
    assert all(chunk["vector"] is None for chunk in data["chunks"])
    assert data["dims"] == 1024
    assert len(data["chunks"]) > 0
    assert "bm25" in data
    assert "clause_map" in data
    assert "SEC-002-2.1" in data["clause_map"]


def test_build_index_invalid_kb_raises(tmp_path: Path) -> None:
    settings = _local_settings_with_index_at(tmp_path)
    bad_kb_dir = tmp_path / "bad_kb"
    (bad_kb_dir / "shared").mkdir(parents=True)
    (bad_kb_dir / "shared" / "BAD-001.md").write_text("no front matter here", encoding="utf-8")

    with pytest.raises(ValueError, match="failed validation"):
        build_index(settings, embeddings="none", upload=False, kb_dir=bad_kb_dir)
