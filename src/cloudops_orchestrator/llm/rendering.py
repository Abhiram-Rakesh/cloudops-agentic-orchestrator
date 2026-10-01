"""Jinja2 rendering for llm/prompts/*.md — never inline f-strings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(str(PROMPTS_DIR)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=False,
)


def render_prompt(template_name: str, **context: Any) -> str:
    template = _env.get_template(template_name)
    return template.render(**context)


__all__ = ["PROMPTS_DIR", "render_prompt"]
