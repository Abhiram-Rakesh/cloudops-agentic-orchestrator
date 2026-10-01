"""respx-mocked tests for integrations/github_client.py — never a live
GitHub call."""

from __future__ import annotations

import base64

import pytest
import respx
from httpx import Response

from cloudops_orchestrator.integrations.github_client import GithubClient

OWNER = "acme"
REPO = "cloudops-demo"
SHA = "a" * 40


@pytest.fixture
def client() -> GithubClient:
    return GithubClient(token="fake-token", owner=OWNER, repo=REPO)


@pytest.fixture
def router() -> respx.MockRouter:
    with respx.mock(base_url="https://api.github.com") as mock_router:
        yield mock_router


class TestGetDefaultBranch:
    def test_returns_default_branch(self, client: GithubClient, router: respx.MockRouter) -> None:
        router.get(f"/repos/{OWNER}/{REPO}").mock(
            return_value=Response(200, json={"id": 1, "name": REPO, "default_branch": "main"})
        )
        assert client.get_default_branch() == "main"


class TestGetRefSha:
    def test_returns_sha(self, client: GithubClient, router: respx.MockRouter) -> None:
        router.get(f"/repos/{OWNER}/{REPO}/git/ref/heads%2Fmain").mock(
            return_value=Response(
                200,
                json={
                    "ref": "refs/heads/main",
                    "node_id": "x",
                    "url": "u",
                    "object": {"sha": SHA, "type": "commit", "url": "u"},
                },
            )
        )
        assert client.get_ref_sha("heads/main") == SHA


class TestCreateBranch:
    def test_creates_ref(self, client: GithubClient, router: respx.MockRouter) -> None:
        route = router.post(f"/repos/{OWNER}/{REPO}/git/refs").mock(
            return_value=Response(
                201,
                json={
                    "ref": "refs/heads/cloudops/x",
                    "node_id": "x",
                    "url": "u",
                    "object": {"sha": SHA, "type": "commit", "url": "u"},
                },
            )
        )
        client.create_branch("cloudops/x", from_sha=SHA)
        assert route.called
        body = route.calls.last.request.content
        assert b"refs/heads/cloudops/x" in body


class TestGetFile:
    def test_decodes_content(self, client: GithubClient, router: respx.MockRouter) -> None:
        raw = 'resource "aws_vpc" "main" {}'
        router.get(f"/repos/{OWNER}/{REPO}/contents/demo%2Finfra%2Fmain.tf").mock(
            return_value=Response(
                200,
                json={
                    "type": "file",
                    "encoding": "base64",
                    "size": len(raw),
                    "name": "main.tf",
                    "path": "demo/infra/main.tf",
                    "content": base64.b64encode(raw.encode()).decode(),
                    "sha": SHA,
                    "url": "u",
                    "git_url": "u",
                    "html_url": "u",
                    "download_url": "u",
                    "_links": {"self": "u", "git": "u", "html": "u"},
                },
            )
        )
        content, sha = client.get_file("demo/infra/main.tf")
        assert content == raw
        assert sha == SHA

    def test_directory_raises(self, client: GithubClient, router: respx.MockRouter) -> None:
        router.get(f"/repos/{OWNER}/{REPO}/contents/demo%2Finfra").mock(
            return_value=Response(200, json=[])
        )
        with pytest.raises(ValueError, match="not a file"):
            client.get_file("demo/infra")


class TestListTerraformFiles:
    def test_recurses_into_directories(
        self, client: GithubClient, router: respx.MockRouter
    ) -> None:
        def dir_item(path: str, *, type_: str) -> dict[str, object]:
            return {
                "type": type_,
                "size": 1,
                "name": path.rsplit("/", 1)[-1],
                "path": path,
                "sha": SHA,
                "url": "u",
                "git_url": "u",
                "html_url": "u",
                "download_url": None,
                "_links": {"self": "u", "git": "u", "html": "u"},
            }

        router.get(f"/repos/{OWNER}/{REPO}/contents/demo%2Finfra").mock(
            return_value=Response(
                200,
                json=[
                    dir_item("demo/infra/main.tf", type_="file"),
                    dir_item("demo/infra/readme.md", type_="file"),
                    dir_item("demo/infra/modules", type_="dir"),
                ],
            )
        )
        router.get(f"/repos/{OWNER}/{REPO}/contents/demo%2Finfra%2Fmodules").mock(
            return_value=Response(200, json=[dir_item("demo/infra/modules/sg.tf", type_="file")])
        )
        files = client.list_terraform_files("demo/infra")
        assert sorted(files) == ["demo/infra/main.tf", "demo/infra/modules/sg.tf"]


class TestCreateOrUpdateFile:
    def test_returns_new_sha(self, client: GithubClient, router: respx.MockRouter) -> None:
        new_sha = "b" * 40
        router.put(f"/repos/{OWNER}/{REPO}/contents/demo%2Finfra%2Fmain.tf").mock(
            return_value=Response(
                200,
                json={
                    "content": {
                        "type": "file",
                        "encoding": "base64",
                        "size": 1,
                        "name": "main.tf",
                        "path": "demo/infra/main.tf",
                        "sha": new_sha,
                        "url": "u",
                        "git_url": "u",
                        "html_url": "u",
                        "download_url": "u",
                        "_links": {"self": "u", "git": "u", "html": "u"},
                    },
                    "commit": {
                        "sha": new_sha,
                        "node_id": "x",
                        "url": "u",
                        "html_url": "u",
                        "author": None,
                        "committer": None,
                        "message": "x",
                        "tree": {"sha": new_sha, "url": "u"},
                        "parents": [],
                        "verification": None,
                    },
                },
            )
        )
        result = client.create_or_update_file(
            "demo/infra/main.tf", message="msg", content="x = 1", branch="cloudops/x", sha=SHA
        )
        assert result == new_sha


class TestCreatePullRequest:
    def test_returns_pr_result(self, client: GithubClient, router: respx.MockRouter) -> None:
        router.post(f"/repos/{OWNER}/{REPO}/pulls").mock(
            return_value=Response(
                201,
                json={
                    "number": 42,
                    "node_id": "PR_x",
                    "html_url": "https://github.com/acme/cloudops-demo/pull/42",
                },
            )
        )
        result = client.create_pull_request(title="x", head="cloudops/x", base="main", body="x")
        assert result.number == 42
        assert result.html_url == "https://github.com/acme/cloudops-demo/pull/42"


class TestAddLabels:
    def test_posts_labels(self, client: GithubClient, router: respx.MockRouter) -> None:
        route = router.post(f"/repos/{OWNER}/{REPO}/issues/42/labels").mock(
            return_value=Response(200, json=[])
        )
        client.add_labels(42, ["cloudops-agent", "tier/T1"])
        assert route.called


class TestDispatchWorkflow:
    def test_dispatches(self, client: GithubClient, router: respx.MockRouter) -> None:
        route = router.post(
            f"/repos/{OWNER}/{REPO}/actions/workflows/demo-apply.yml/dispatches"
        ).mock(return_value=Response(204))
        client.dispatch_workflow("demo-apply.yml", ref="main", inputs={"action_id": "a1"})
        assert route.called


class TestListRecentWorkflowRuns:
    def test_returns_runs_created_after(
        self, client: GithubClient, router: respx.MockRouter
    ) -> None:
        route = router.get(f"/repos/{OWNER}/{REPO}/actions/workflows/prowler.yml/runs").mock(
            return_value=Response(
                200,
                json={
                    "total_count": 1,
                    "workflow_runs": [{"id": 1, "status": "completed", "conclusion": "success"}],
                },
            )
        )
        runs = client.list_recent_workflow_runs(
            "prowler.yml", created_after_iso="2026-01-01T00:00:00Z"
        )
        assert route.called
        assert route.calls.last.request.url.params["created"] == ">=2026-01-01T00:00:00Z"
        assert runs == [{"id": 1, "status": "completed", "conclusion": "success"}]

    def test_no_runs_returns_empty_list(
        self, client: GithubClient, router: respx.MockRouter
    ) -> None:
        router.get(f"/repos/{OWNER}/{REPO}/actions/workflows/drift.yml/runs").mock(
            return_value=Response(200, json={"total_count": 0, "workflow_runs": []})
        )
        assert (
            client.list_recent_workflow_runs("drift.yml", created_after_iso="2026-01-01T00:00:00Z")
            == []
        )
