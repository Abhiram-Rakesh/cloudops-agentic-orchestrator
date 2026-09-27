from __future__ import annotations

import json

import pytest

from cloudops_orchestrator.logging import bind_context, configure_logging, get_logger


def test_log_output_is_json_with_bound_context(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()
    logger = get_logger()
    with bind_context(run_id="run-123"):
        logger.info("collect.finished", findings=3)

    captured = capsys.readouterr()
    line = captured.out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["event"] == "collect.finished"
    assert payload["run_id"] == "run-123"
    assert payload["findings"] == 3
    assert payload["level"] == "info"


def test_context_reset_after_block(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()
    logger = get_logger()
    with bind_context(run_id="run-abc"):
        pass
    logger.info("after.block")

    captured = capsys.readouterr()
    line = captured.out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert "run_id" not in payload
