"""Parse and validate SOP markdown files against the schema in
``knowledge_base/README.md``.

A SOP file is YAML front-matter (parsed with ``python-frontmatter``) followed
by markdown body text containing ``### <CLAUSE_ID> — <title>`` headings, each
immediately followed by a fenced ```clause-meta``` YAML block and then prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import frontmatter
import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from cloudops_orchestrator.models.enums import ActionType, KBDomain, Severity

_ACTION_TYPE_VALUES = {member.value for member in ActionType}
_VALID_RISK_TIER_KEYS = {"non_prod", "prod"}
_VALID_RISK_TIER_VALUES = {"T0", "T1", "T2", "T3"}

_HEADING_RE = re.compile(r"^(?P<hashes>#{2,3}) (?P<text>.+)$", re.MULTILINE)
_CLAUSE_HEADING_RE = re.compile(r"^(?P<clause_id>[A-Z]+-\d+-\d+\.\d+) — (?P<title>.+)$")
_CLAUSE_META_FENCE_RE = re.compile(r"```clause-meta\n(?P<yaml>.*?)\n```", re.DOTALL)


class SOPParseError(ValueError):
    """A structural error in a SOP file (missing front matter, bad heading, ...)."""


class SOPFrontMatter(BaseModel):
    model_config = ConfigDict(frozen=True)

    sop_id: str
    title: str
    domain: KBDomain
    version: str
    owner: str
    effective_date: date
    review_cycle_days: int
    applies_to: list[str]
    references: list[str] = []


class ClauseMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    controls: list[str] = []
    prowler_checks: list[str] = []
    severity: Severity | None = None
    default_action: str | None = None
    iac_managed_action: str | None = None
    risk_tier: dict[str, str] = {}
    references: list[str] = []

    @field_validator("default_action", "iac_managed_action")
    @classmethod
    def _validate_action_spec(cls, value: str | None) -> str | None:
        if value is None:
            return value
        action_type = value.split(":", 1)[0]
        if action_type not in _ACTION_TYPE_VALUES:
            allowed = ", ".join(sorted(_ACTION_TYPE_VALUES))
            msg = (
                f"Unknown action_type {action_type!r} in action spec {value!r} (allowed: {allowed})"
            )
            raise ValueError(msg)
        return value

    @field_validator("risk_tier")
    @classmethod
    def _validate_risk_tier(cls, value: dict[str, str]) -> dict[str, str]:
        for key, tier in value.items():
            if key not in _VALID_RISK_TIER_KEYS:
                msg = f"risk_tier key {key!r} must be one of {sorted(_VALID_RISK_TIER_KEYS)}"
                raise ValueError(msg)
            if tier not in _VALID_RISK_TIER_VALUES:
                msg = f"risk_tier value {tier!r} must be one of {sorted(_VALID_RISK_TIER_VALUES)}"
                raise ValueError(msg)
        return value


@dataclass(frozen=True)
class Clause:
    clause_id: str
    title: str
    meta: ClauseMeta
    body: str


@dataclass(frozen=True)
class SOPDocument:
    front_matter: SOPFrontMatter
    overview_text: str
    clauses: list[Clause] = field(default_factory=list)
    source_path: str = ""


def parse_action_spec(spec: str) -> tuple[str, str | None]:
    """Split ``"ssm_automation:CloudOps-RevokeSGIngressWorld"`` into (action_type, param)."""
    action_type, _, param = spec.partition(":")
    return action_type, (param or None)


def _split_headings(body: str) -> list[tuple[int, int, int, str]]:
    """Return (start, end_of_line, level, heading_text) for every ## / ### heading."""
    headings = []
    for match in _HEADING_RE.finditer(body):
        level = len(match.group("hashes"))
        headings.append((match.start(), match.end(), level, match.group("text")))
    return headings


def _parse_clause_meta(clause_id: str, clause_text: str) -> tuple[ClauseMeta, str]:
    match = _CLAUSE_META_FENCE_RE.search(clause_text)
    if match is None:
        msg = f"Clause {clause_id} has no fenced ```clause-meta``` block"
        raise SOPParseError(msg)
    raw_yaml = yaml.safe_load(match.group("yaml")) or {}
    try:
        meta = ClauseMeta.model_validate(raw_yaml)
    except ValidationError as exc:
        msg = f"Clause {clause_id} has an invalid clause-meta block: {exc}"
        raise SOPParseError(msg) from exc
    prose = clause_text[: match.start()] + clause_text[match.end() :]
    return meta, prose.strip()


def parse_sop_text(text: str, *, source_path: str = "") -> SOPDocument:
    post = frontmatter.loads(text)
    if not post.metadata:
        msg = f"{source_path}: missing YAML front matter"
        raise SOPParseError(msg)
    try:
        front_matter = SOPFrontMatter.model_validate(post.metadata)
    except ValidationError as exc:
        msg = f"{source_path}: invalid front matter: {exc}"
        raise SOPParseError(msg) from exc

    body = post.content
    headings = _split_headings(body)

    clause_headings: list[tuple[int, int, str, str]] = []  # (start, end, clause_id, title)
    for start, end, level, text_ in headings:
        if level != 3:
            continue
        clause_match = _CLAUSE_HEADING_RE.match(text_)
        if clause_match is None:
            continue
        clause_headings.append(
            (start, end, clause_match.group("clause_id"), clause_match.group("title"))
        )

    overview_text = body[: clause_headings[0][0]].strip() if clause_headings else body.strip()

    clauses: list[Clause] = []
    for _start, end, clause_id, title in clause_headings:
        next_heading_start = _next_heading_start(headings, end)
        clause_text = body[end:next_heading_start]
        meta, prose = _parse_clause_meta(clause_id, clause_text)
        clauses.append(Clause(clause_id=clause_id, title=title, meta=meta, body=prose))

    return SOPDocument(
        front_matter=front_matter,
        overview_text=overview_text,
        clauses=clauses,
        source_path=source_path,
    )


def _next_heading_start(headings: list[tuple[int, int, int, str]], after: int) -> int:
    for start, _end, _level, _text in headings:
        if start >= after:
            return start
    return 10**12  # sentinel "end of document"


def parse_sop_file(path: Path) -> SOPDocument:
    text = path.read_text(encoding="utf-8")
    return parse_sop_text(text, source_path=str(path))


def discover_sop_files(kb_dir: Path) -> list[Path]:
    return sorted(p for p in kb_dir.rglob("*.md") if p.name != "README.md")


def parse_knowledge_base(kb_dir: Path) -> list[SOPDocument]:
    return [parse_sop_file(path) for path in discover_sop_files(kb_dir)]


def validate_knowledge_base(kb_dir: Path) -> list[str]:
    """Validate every SOP's structure and cross-references. Returns error strings (empty = valid)."""
    errors: list[str] = []
    documents: list[SOPDocument] = []

    for path in discover_sop_files(kb_dir):
        try:
            documents.append(parse_sop_file(path))
        except SOPParseError as exc:
            errors.append(str(exc))

    if errors:
        return errors

    all_sop_ids = {doc.front_matter.sop_id for doc in documents}
    all_clause_ids: dict[str, str] = {}  # clause_id -> source_path

    for doc in documents:
        sop_id = doc.front_matter.sop_id
        expected_prefix = f"{sop_id}-"
        for clause in doc.clauses:
            if not clause.clause_id.startswith(expected_prefix):
                errors.append(
                    f"{doc.source_path}: clause {clause.clause_id} does not start with "
                    f"the SOP's own id prefix {expected_prefix!r}"
                )
            if clause.clause_id in all_clause_ids:
                errors.append(
                    f"{doc.source_path}: duplicate clause_id {clause.clause_id} "
                    f"(also defined in {all_clause_ids[clause.clause_id]})"
                )
            all_clause_ids[clause.clause_id] = doc.source_path

        for ref in doc.front_matter.references:
            if ref not in all_sop_ids:
                errors.append(f"{doc.source_path}: front matter references unknown sop_id {ref!r}")

    for doc in documents:
        for clause in doc.clauses:
            for ref in clause.meta.references:
                if ref not in all_clause_ids and ref not in all_sop_ids:
                    errors.append(
                        f"{doc.source_path}: clause {clause.clause_id} references unknown "
                        f"clause_id/sop_id {ref!r}"
                    )

    return errors


def clause_meta_index(kb_dir: Path) -> dict[str, ClauseMeta]:
    """Map every clause_id in the knowledge base to its parsed ``ClauseMeta``."""
    index: dict[str, ClauseMeta] = {}
    for doc in parse_knowledge_base(kb_dir):
        for clause in doc.clauses:
            index[clause.clause_id] = clause.meta
    return index


def clause_text_index(kb_dir: Path) -> dict[str, str]:
    """Map every clause_id to its full prose (title + body) — used by the
     policy engine to verify a citation's ``quote`` is a verbatim substring
    ."""
    index: dict[str, str] = {}
    for doc in parse_knowledge_base(kb_dir):
        for clause in doc.clauses:
            index[clause.clause_id] = f"{clause.title}\n{clause.body}"
    return index


__all__ = [
    "Clause",
    "ClauseMeta",
    "SOPDocument",
    "SOPFrontMatter",
    "SOPParseError",
    "clause_meta_index",
    "clause_text_index",
    "discover_sop_files",
    "parse_action_spec",
    "parse_knowledge_base",
    "parse_sop_file",
    "parse_sop_text",
    "validate_knowledge_base",
]
