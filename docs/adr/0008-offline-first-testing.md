# 0008 — Offline-first testing: fixtures/moto/Stubber/respx everywhere, no paid API calls ever from tests

## Status

Accepted. Amended 2026-10-01: the fake LLM (`FakeChatModel`), the fake
embedder, the local sequential runner (`make run-local`) and the eval suite
built on them were removed. Tests that need a model are no longer written;
the LLM path is exercised only against the deployed system.

## Context

This system's own build process, CI, and local development must never call
Anthropic, LangSmith, Slack, Bedrock, or make a real AWS write call — both
because of cost (an LLM call per test run, at CI's PR-and-push frequency,
would be neither cheap nor deterministic) and because of safety (a test
suite that can accidentally mutate a real cloud account or send a real
Slack message is a standing hazard, independent of who's running it).

Alternatives considered: record-and-replay cassettes against real API
responses (e.g. VCR-style) captured once and replayed thereafter (rejected
as the primary strategy — still requires an initial real call to record,
and silently goes stale as APIs evolve without an obvious signal); mocking
at the HTTP-client level only, with hand-rolled model classes for
everything else (this is close to what was actually built, generalized
into the pattern below).

## Decision

Every external dependency other than the LLM has a purpose-built offline
stand-in, used everywhere in tests:

- **LLM and embedding calls:** never made in tests, and there is no fake
  stand-in. The KB can be built BM25-only (`kb build --embeddings none`),
  which needs no Bedrock call.
- **AWS calls:** `moto` (integration tests) or `botocore.stub.Stubber`
  (unit tests) for anything touching a real boto3 client, including the
  single-table store (see ADR 0003).
- **GitHub calls:** `respx`-mocked HTTP responses against `githubkit`'s
  client.
- **Slack calls:** never made in tests at all — `slack_handler`'s own
  signature verification and authorization logic are unit-tested directly
  against synthetic payloads, without a real Slack round-trip.

## Consequences

- Test doubles are a maintenance surface: the `moto` table fixtures must
  mirror the real table's schema (including the case-sensitive `gsi1`
  index name, which once diverged and hid a live bug).
- Coverage of the stubbed paths doesn't prove the *real* integration
  works — the README's Troubleshooting section tracks what only a live
  deploy surfaced.
- The agent graph, structured-output path and Terraform-PR drafting have no
  automated tests, since they need a model. A regression there is only
  caught against the deployed system.
- The remaining suite runs in well under a minute, deterministically, on a
  machine with no AWS credentials, no Anthropic key, and no Slack
  workspace.
