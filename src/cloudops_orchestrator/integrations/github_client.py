"""Thin wrapper around githubkit's synchronous REST client.

Auth: a plain bearer token the caller fetches from Parameter Store at cold
start — a fine-grained PAT by default, or a GitHub App installation token
(``github.auth_mode`` only documents which kind of token is expected; both
are just bearer tokens to githubkit, so this module doesn't need to know
which). GitHub is the only external system this project ever writes to; every write
here is exercised in tests only against a respx-mocked ``https://api.github.com``, never a live account.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from githubkit import GitHub

DEFAULT_COMMITTER_NAME = "CloudOps Agent"
DEFAULT_COMMITTER_EMAIL = "cloudops-agent@users.noreply.github.com"


@dataclass(frozen=True)
class PullRequestResult:
    number: int
    html_url: str
    node_id: str


class GithubClient:
    def __init__(self, *, token: str, owner: str, repo: str) -> None:
        self._gh = GitHub(token)
        self.owner = owner
        self.repo = repo

    def get_default_branch(self) -> str:
        response = self._gh.rest.repos.get(owner=self.owner, repo=self.repo)
        data: Any = response.json()
        branch: str = data["default_branch"]
        return branch

    def get_ref_sha(self, ref: str) -> str:
        response = self._gh.rest.git.get_ref(owner=self.owner, repo=self.repo, ref=ref)
        sha: str = response.parsed_data.object_.sha
        return sha

    def create_branch(self, branch_name: str, *, from_sha: str) -> None:
        self._gh.rest.git.create_ref(
            owner=self.owner, repo=self.repo, ref=f"refs/heads/{branch_name}", sha=from_sha
        )

    def get_file(self, path: str, *, ref: str | None = None) -> tuple[str, str]:
        """Returns ``(decoded_text_content, blob_sha)``."""
        kwargs: dict[str, Any] = {"owner": self.owner, "repo": self.repo, "path": path}
        if ref is not None:
            kwargs["ref"] = ref
        response = self._gh.rest.repos.get_content(**kwargs)
        data: Any = response.json()
        if not isinstance(data, dict) or data.get("content") is None:
            msg = f"{path!r} is not a file (directory or symlink?)"
            raise ValueError(msg)
        return base64.b64decode(data["content"]).decode("utf-8"), data["sha"]

    def list_terraform_files(self, path: str, *, ref: str | None = None) -> list[str]:
        """Recursively list every ``.tf`` file under ``path``."""
        kwargs: dict[str, Any] = {"owner": self.owner, "repo": self.repo, "path": path}
        if ref is not None:
            kwargs["ref"] = ref
        response = self._gh.rest.repos.get_content(**kwargs)
        items: Any = response.json()
        if not isinstance(items, list):
            return [path] if path.endswith(".tf") else []
        files: list[str] = []
        for item in items:
            if item["type"] == "dir":
                files.extend(self.list_terraform_files(item["path"], ref=ref))
            elif item["type"] == "file" and item["path"].endswith(".tf"):
                files.append(item["path"])
        return files

    def create_or_update_file(
        self, path: str, *, message: str, content: str, branch: str, sha: str
    ) -> str:
        """Returns the new file's blob sha."""
        response = self._gh.rest.repos.create_or_update_file_contents(
            owner=self.owner,
            repo=self.repo,
            path=path,
            message=message,
            content=base64.b64encode(content.encode("utf-8")).decode("ascii"),
            branch=branch,
            sha=sha,
            committer={"name": DEFAULT_COMMITTER_NAME, "email": DEFAULT_COMMITTER_EMAIL},
            author={"name": DEFAULT_COMMITTER_NAME, "email": DEFAULT_COMMITTER_EMAIL},
        )
        response_data: Any = response.json()
        content_data = response_data.get("content")
        if content_data is None:
            msg = "create_or_update_file_contents returned no content"
            raise RuntimeError(msg)
        new_sha: str = content_data["sha"]
        return new_sha

    def create_pull_request(
        self, *, title: str, head: str, base: str, body: str, draft: bool = True
    ) -> PullRequestResult:
        response = self._gh.rest.pulls.create(
            owner=self.owner,
            repo=self.repo,
            title=title,
            head=head,
            base=base,
            body=body,
            draft=draft,
        )
        pr: Any = response.json()
        return PullRequestResult(
            number=pr["number"], html_url=pr["html_url"], node_id=pr["node_id"]
        )

    def add_labels(self, pr_number: int, labels: list[str]) -> None:
        self._gh.rest.issues.add_labels(
            owner=self.owner, repo=self.repo, issue_number=pr_number, labels=labels
        )

    def dispatch_workflow(
        self, workflow_file: str, *, ref: str, inputs: dict[str, str] | None = None
    ) -> None:
        self._gh.rest.actions.create_workflow_dispatch(
            owner=self.owner,
            repo=self.repo,
            workflow_id=workflow_file,
            ref=ref,
            inputs=inputs or {},
        )

    def list_recent_workflow_runs(self, workflow_file: str, *, created_after_iso: str) -> list[Any]:
        """Runs of ``workflow_file`` created at/after ``created_after_iso``
        (an ISO-8601 timestamp) — used to poll a just-dispatched run for
        completion, since ``create_workflow_dispatch`` returns no run ID."""
        response = self._gh.rest.actions.list_workflow_runs(
            owner=self.owner,
            repo=self.repo,
            workflow_id=workflow_file,
            created=f">={created_after_iso}",
        )
        data: Any = response.json()
        runs: list[Any] = data.get("workflow_runs", []) if isinstance(data, dict) else []
        return runs


__all__ = ["DEFAULT_COMMITTER_EMAIL", "DEFAULT_COMMITTER_NAME", "GithubClient", "PullRequestResult"]
