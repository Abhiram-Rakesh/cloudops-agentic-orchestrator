# 0007 — Fine-grained PAT as the default GitHub auth mode, GitHub App as a documented future option

## Status

Accepted (GitHub App mode: accepted as a future direction, not yet implemented).

## Context

The Terraform PR agent needs a GitHub identity with Contents, Pull
requests, and Actions write access, scoped to exactly this one repo. Two
standard mechanisms exist: a fine-grained personal access token, or a
GitHub App installed on the repo. A GitHub App is generally the better
practice for multi-repo, multi-installer, or organization-wide tooling —
it's audited separately from any individual's account, survives that
individual leaving, and can be scoped per-installation.

Alternatives considered: a classic (non-fine-grained) PAT (rejected —
classic PATs can't be scoped to a single repository, so a leaked token
would expose every repo the account can access); OAuth app / user-token
flow (rejected — designed for interactive multi-user authorization, not a
fit for a single-repo background agent).

## Decision

Default to a fine-grained PAT, scoped to this repo only, with exactly the
three permissions the agent needs (Contents, Pull requests, Actions:
read/write). `github.auth_mode: app` is accepted as a valid config value
and noted in the README, but `GithubClient` does not
implement the App-installation-token exchange yet — building it is
deferred until it's actually needed (multiple repos, or a rotating set of
maintainers, neither of which applies to this single-maintainer, single-
repo project today).

## Consequences

- The fine-grained PAT has an expiration a human must remember to rotate
  (`scripts/put_parameters.sh` makes this a one-command operation, but it's
  still a manual trigger, not automatic).
- The README notes that `auth_mode:
  app` must not be set until the App-auth code path is actually built and
  tested — setting it today would silently fail (or worse, fall through to
  unexpected behavior) since nothing implements that branch's token
  exchange.
- If this project ever needs App-mode (more repos, a team rather than a
  solo maintainer), the config surface (`github.auth_mode`) already exists
  and doesn't need a breaking change — only `integrations/github_client.py`
  needs the new branch implemented, wired to `githubkit`'s
  `AppInstallationAuthStrategy` (exact class/kwargs to be re-verified
  against whatever `githubkit` version is installed at that time).
