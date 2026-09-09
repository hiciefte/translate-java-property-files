from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
import json
from typing import Any

import httpx
import pytest

from localize.guardian import remediation as remediation_module
from localize.guardian.credentials import (
    SecretCommand,
    credential_snapshot,
    git_credential_environment,
)
from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.github import GitHubAuthenticationError, OpenPullPathIdentity
from localize.guardian.models import (
    AllowedHeadRepository,
    ClosedPrBackfillPolicy,
    ExactRepository,
    HistoricalRemediationPolicy,
    HistoricalCheckScope,
    ProposedReplacement,
    RepositoryPolicy,
    TrustedActor,
)
from localize.guardian.policy import PatchResult
from localize.guardian.remediation import (
    RemediationBatchOutcome,
    RemediationDraftResult,
    RemediationCoordinator,
    RemediationGitHubBroker,
    RemediationOpenPullAuthorityError,
    RemediationRemoteConflictError,
    RemediationRuntimeError,
    RemediationSourceAuthorityError,
)
from localize.guardian.state import (
    HistoricalPullReference,
    MergedRemediationRevalidation,
    RemediationDraftRecord,
    RemediationEditCoverage,
    RemediationSuccessorIntent,
    RemediationSuccessorPublication,
    remediation_batch_hash,
    remediation_edit_hash,
    remediation_target_hash,
)
from localize.guardian.workspace import (
    CommitResult,
    ExactRevision,
    PreventionPublicationResult,
)


BASE_SHA = "a" * 40
CANDIDATE_SHA = "b" * 40


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _AdvancingStream(httpx.SyncByteStream):
    def __init__(
        self,
        clock: _FakeClock,
        chunks: tuple[tuple[float, bytes], ...],
    ) -> None:
        self.clock = clock
        self.chunks = chunks

    def __iter__(self):
        for delay, chunk in self.chunks:
            self.clock.advance(delay)
            yield chunk


def _policy() -> RepositoryPolicy:
    author = TrustedActor("translator", 7, "User")
    owner = TrustedActor("translator", 8, "Organization")
    return RepositoryPolicy(
        base_repo="acme/translations",
        base_repo_id=42,
        base_branch="main",
        allowed_pr_authors=(author,),
        allowed_head_owners=(owner,),
        allowed_head_repositories=(
            AllowedHeadRepository("translator/translations", 84),
        ),
        allowed_branch_globs=(
            "translation-updates-*",
            "translation-updates-history-*",
        ),
        allowed_path_globs=("l10n/*.properties",),
        pipeline_config_path="config.yaml",
        source_locale="en",
        trusted_reviewers={"ru": (TrustedActor("reviewer", 9, "User"),)},
        trusted_bots={},
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=120,
            max_prs_per_poll=4,
            remediation=HistoricalRemediationPolicy(
                push_repository=ExactRepository(
                    full_name="translator/translations",
                    id=84,
                ),
                push_branch_prefix="translation-updates-history-",
                publication_actor=author,
            ),
        ),
    )


def _response(
    request: httpx.Request, payload: object, status: int = 200
) -> httpx.Response:
    return httpx.Response(status, request=request, json=payload)


def _repo(
    full_name: str,
    repository_id: int,
    *,
    owner_id: int = 8,
    owner_type: str = "Organization",
    private: bool = False,
    fork: bool | None = None,
    parent_id: int = 42,
    network_root_id: int = 42,
) -> dict[str, object]:
    if fork is None:
        fork = full_name == "translator/translations"
    payload: dict[str, object] = {
        "full_name": full_name,
        "id": repository_id,
        "private": private,
        "fork": fork,
        "owner": {"id": owner_id, "type": owner_type},
    }
    if fork:
        payload.update(
            parent={"id": parent_id},
            source={"id": network_root_id, "fork": False},
        )
    return payload


def _branch(name: str, sha: str) -> dict[str, object]:
    return {"name": name, "commit": {"sha": sha}}


def _pull(
    *,
    branch: str,
    title: str,
    body: str,
    base_sha: str = BASE_SHA,
    base_ref: str = "main",
    state: str = "open",
    merged_at: str | None = None,
    closed_at: str | None | object = ...,
    updated_at: str = "2026-09-03T08:00:00Z",
    draft: bool = True,
    maintainer_can_modify: bool = False,
    html_url: str = "https://github.test/acme/translations/pull/91",
    author: object | None = None,
) -> dict[str, object]:
    if closed_at is ...:
        closed_at = merged_at or "2026-09-03T08:00:00Z" if state == "closed" else None
    return {
        "id": 9_091,
        "number": 91,
        "html_url": html_url,
        "state": state,
        "merged_at": merged_at,
        "closed_at": closed_at,
        "updated_at": updated_at,
        "draft": draft,
        "maintainer_can_modify": maintainer_can_modify,
        "title": title,
        "body": body,
        "user": author or {"login": "translator", "id": 7, "type": "User"},
        "head": {
            "ref": branch,
            "sha": CANDIDATE_SHA,
            "repo": {"full_name": "translator/translations", "id": 84},
        },
        "base": {
            "ref": base_ref,
            "sha": base_sha,
            "repo": {"full_name": "acme/translations", "id": 42},
        },
    }


def _issue_event(event_id: int, event: str) -> dict[str, object]:
    return {"id": event_id, "event": event}


def _broker(
    handler,
    *,
    policy: RepositoryPolicy | None = None,
    actor: object | None = None,
    deadline: PollDeadline | None = None,
) -> RemediationGitHubBroker:
    authenticated_actor = (
        {"login": "translator", "id": 7, "type": "User"} if actor is None else actor
    )

    def authenticated_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(request, authenticated_actor)
        return handler(request)

    broker = RemediationGitHubBroker(
        policy=policy or _policy(),
        token_command=("/usr/bin/printf", "unit-test-token"),
        github_host="github.test",
        base_url="https://api.github.test",
        transport=httpx.MockTransport(authenticated_handler),
        deadline=deadline,
    )
    return broker


def test_remediation_broker_deadline_stops_trickling_response() -> None:
    clock = _FakeClock()
    payload = json.dumps(_repo("acme/translations", 42)).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/acme/translations"
        midpoint = len(payload) // 2
        return httpx.Response(
            200,
            request=request,
            stream=_AdvancingStream(
                clock,
                ((0.0, payload[:midpoint]), (1.1, payload[midpoint:])),
            ),
        )

    broker = _broker(
        handler,
        deadline=PollDeadline(1, clock=clock),
    )

    with pytest.raises(PollDeadlineExceeded):
        broker.capture_base()


def test_remediation_pagination_reclamps_each_page_to_remaining_deadline() -> None:
    clock = _FakeClock()
    observed_timeouts: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/acme/translations/issues/91/events"
        observed_timeouts.append(request.extensions["timeout"])
        page = int(request.url.params["page"])
        if page == 1:
            clock.advance(3)
            return _response(
                request,
                [_issue_event(item_id, "commented") for item_id in range(1, 101)],
            )
        return _response(request, [_issue_event(101, "commented")])

    broker = _broker(
        handler,
        deadline=PollDeadline(10, clock=clock),
    )
    with broker._client() as (client, _actor):  # noqa: SLF001
        assert broker._pull_event_history(client, number=91) == ()  # noqa: SLF001

    assert set(observed_timeouts[0].values()) == {2.5}
    assert set(observed_timeouts[1].values()) == {1.75}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"created": "yes"}, "flags"),
        ({"draft": 1}, "flags"),
        ({"merged": 1}, "flags"),
        ({"created": True, "draft": False}, "open drafts"),
        ({"created": True, "state": "closed"}, "open drafts"),
        ({"state": "open", "merged": True, "draft": False}, "merged"),
        ({"state": "closed", "merged": True}, "merged"),
        ({"base_sha": "short"}, "base SHA"),
    ],
)
def test_remediation_draft_result_rejects_inconsistent_lifecycle(
    overrides: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "number": 91,
        "html_url": "https://github.test/acme/translations/pull/91",
        "candidate_sha": CANDIDATE_SHA,
        "created": False,
    }
    values.update(overrides)

    with pytest.raises(ValueError, match=message):
        RemediationDraftResult(**values)  # type: ignore[arg-type]


def test_capture_base_pins_target_and_push_repository_numeric_identities() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        raise AssertionError(request.url)

    snapshot = _broker(handler).capture_base()

    assert snapshot.revision.sha == BASE_SHA
    assert snapshot.revision.ref == "refs/heads/main"
    assert snapshot.target_repository_id == 42
    assert snapshot.push_repository_id == 84
    assert requests == [
        "/repos/acme/translations",
        "/repos/translator/translations",
        "/repos/acme/translations/branches/main",
    ]


def test_capture_base_allows_same_repository_publication() -> None:
    policy = _policy()
    assert policy.closed_pr_backfill is not None
    assert policy.closed_pr_backfill.remediation is not None
    policy = replace(
        policy,
        allowed_head_repositories=(
            *policy.allowed_head_repositories,
            AllowedHeadRepository("acme/translations", 42),
        ),
        closed_pr_backfill=replace(
            policy.closed_pr_backfill,
            remediation=replace(
                policy.closed_pr_backfill.remediation,
                push_repository=ExactRepository("acme/translations", 42),
            ),
        ),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        raise AssertionError(request.url)

    snapshot = _broker(handler, policy=policy).capture_base()

    assert snapshot.target_repository_id == snapshot.push_repository_id == 42


def test_capture_base_allows_sibling_forks_in_one_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(
                request,
                _repo(
                    "acme/translations",
                    42,
                    fork=True,
                    parent_id=40,
                    network_root_id=40,
                ),
            )
        if request.url.path == "/repos/translator/translations":
            return _response(
                request,
                _repo(
                    "translator/translations",
                    84,
                    parent_id=41,
                    network_root_id=40,
                ),
            )
        if request.url.path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        raise AssertionError(request.url)

    snapshot = _broker(handler).capture_base()

    assert snapshot.target_repository_id == 42
    assert snapshot.push_repository_id == 84


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/repos/acme/translations", _repo("acme/translations", 999)),
        (
            "/repos/translator/translations",
            _repo("attacker/translations", 84),
        ),
        (
            "/repos/acme/translations/branches/main",
            _branch("other", BASE_SHA),
        ),
        (
            "/repos/acme/translations/branches/main",
            _branch("main", "short"),
        ),
    ],
)
def test_capture_base_rejects_identity_ref_and_sha_drift(path, payload) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        defaults = {
            "/repos/acme/translations": _repo("acme/translations", 42),
            "/repos/translator/translations": _repo(
                "translator/translations",
                84,
            ),
            "/repos/acme/translations/branches/main": _branch("main", BASE_SHA),
        }
        return _response(
            request, payload if request.url.path == path else defaults[request.url.path]
        )

    with pytest.raises(RemediationRuntimeError):
        _broker(handler).capture_base()


@pytest.mark.parametrize(
    ("owner_id", "owner_type"),
    [(999, "Organization"), (8, "User")],
)
def test_capture_base_rejects_push_repository_owner_identity_drift(
    owner_id: int,
    owner_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(
                request,
                _repo(
                    "translator/translations",
                    84,
                    owner_id=owner_id,
                    owner_type=owner_type,
                ),
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRuntimeError, match="owner identity"):
        _broker(handler).capture_base()


@pytest.mark.parametrize(("member", "invalid_id"), [("source", "42"), ("parent", True)])
def test_capture_base_rejects_malformed_numeric_fork_identity(
    member: str,
    invalid_id: object,
) -> None:
    push = _repo("translator/translations", 84)
    nested = dict(push[member])  # type: ignore[arg-type]
    nested["id"] = invalid_id
    push[member] = nested

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, push)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRuntimeError, match=f"{member} repository id"):
        _broker(handler).capture_base()


@pytest.mark.parametrize("unsafe_relationship", ["private-to-public", "unrelated"])
def test_coordinator_refuses_unsafe_push_repository_before_publication_callback(
    unsafe_relationship: str,
) -> None:
    private_target = unsafe_relationship == "private-to-public"
    target = _repo("acme/translations", 42, private=private_target)
    push = _repo(
        "translator/translations",
        84,
        private=False,
        network_root_id=999 if unsafe_relationship == "unrelated" else 42,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, target)
        if request.url.path == "/repos/translator/translations":
            return _response(request, push)
        raise AssertionError(request.url)

    order: list[str] = []
    base = _base_snapshot(private=private_target)
    state = _StateSpy(order=order)
    workspace = _WorkspaceSpy(base, order=order)
    coordinator = _coordinator(state, _broker(handler))  # type: ignore[arg-type]

    with pytest.raises(RemediationRuntimeError, match="public|fork network"):
        _publish(coordinator, workspace, base)

    assert workspace.publish_calls == []
    assert "remote:branch-push" not in order


@pytest.mark.parametrize("unsafe_relationship", ["private-to-public", "unrelated"])
def test_coordinator_revalidates_repository_relationship_immediately_before_push(
    unsafe_relationship: str,
) -> None:
    private_target = unsafe_relationship == "private-to-public"
    push_repository_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal push_repository_requests
        path = request.url.path
        if path == "/repos/acme/translations":
            return _response(
                request,
                _repo("acme/translations", 42, private=private_target),
            )
        if path == "/repos/translator/translations":
            push_repository_requests += 1
            changed = push_repository_requests >= 3
            return _response(
                request,
                _repo(
                    "translator/translations",
                    84,
                    private=private_target and not changed,
                    network_root_id=(
                        999 if unsafe_relationship == "unrelated" and changed else 42
                    ),
                ),
            )
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        if path.startswith("/repos/translator/translations/branches/"):
            return _response(request, {"message": "Not Found"}, 404)
        raise AssertionError(request.url)

    order: list[str] = []
    base = _base_snapshot(private=private_target)
    state = _StateSpy(order=order)
    workspace = _WorkspaceSpy(base, order=order)
    coordinator = _coordinator(state, _broker(handler))  # type: ignore[arg-type]

    with pytest.raises(RemediationRuntimeError, match="public|fork network"):
        _publish(coordinator, workspace, base)

    assert len(workspace.publish_calls) == 1
    assert "remote:branch-push" not in order


@pytest.mark.parametrize(
    "branch",
    [
        "translation-updates-history-bad~ref",
        "translation-updates-history-bad^ref",
        "translation-updates-history-bad:ref",
        "translation-updates-history-bad?ref",
        "translation-updates-history-bad*ref",
        "translation-updates-history-bad[ref",
        "translation-updates-history-bad\\ref",
        "translation-updates-history-bad\x01ref",
        "translation-updates-history-double//slash",
        "translation-updates-history-double..dot",
        "translation-updates-history-at@{brace",
        "translation-updates-history-trailing.",
        "translation-updates-history-trailing/",
        "translation-updates-history-valid/.hidden/ref",
        "translation-updates-history-lock/ref.lock",
    ],
)
def test_rejects_noncanonical_remediation_branches_before_network(branch: str) -> None:
    broker = _broker(lambda request: pytest.fail(f"unexpected request: {request.url}"))

    with pytest.raises(ValueError, match="branch"):
        broker.branch_sha(branch)


def test_policy_rejects_remediation_namespace_without_exact_allowlist() -> None:
    prefix = "translation-updates-history-"
    with pytest.raises(ValueError, match="allowed head branch"):
        replace(
            _policy(),
            allowed_branch_globs=(
                f"{prefix}candidate",
                f"{prefix}{'0' * 64}",
            ),
        )


def test_remediation_marker_contains_only_stable_evidence_and_candidate_ids() -> None:
    evidence_hash = "c" * 64

    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)

    assert marker == (
        "<!-- localize-guardian-remediation:v1 "
        f"evidence={evidence_hash} candidate={CANDIDATE_SHA} -->"
    )


@pytest.mark.parametrize(
    "html_url",
    [
        "https://attacker.test/acme/translations/pull/91",
        "https://github.test/acme/translations/pull/92",
        "https://user@github.test/acme/translations/pull/91",
        "https://github.test/acme/translations/pull/91?token=x",
        "https://github.test/acme/translations/pull/91#fragment",
    ],
)
def test_recovered_draft_url_must_match_exact_web_host_repo_and_number(
    html_url: str,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(
                request,
                [
                    _pull(
                        branch=branch,
                        title="Human review",
                        body=f"{marker}\nHuman review only.",
                        html_url=html_url,
                    )
                ],
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="URL"):
        _broker(handler).open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Human review",
            body="Human review only.",
            before_create=lambda: pytest.fail("must recover without mutation"),
            before_post=lambda: pytest.fail("must recover without mutation"),
        )


def test_pull_lookup_searches_all_bases_and_fails_closed_on_retarget() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            assert "base" not in request.url.params
            return _response(
                request,
                [
                    _pull(
                        branch=branch,
                        title="title",
                        body=f"{marker}\nbody",
                        base_ref="release",
                    )
                ],
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="exact policy"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


def test_pull_lookup_rejects_duplicates_on_the_first_page() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pulls_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal pulls_requests
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            pulls_requests += 1
            pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")
            return _response(request, [pull, pull])
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="duplicate"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )
    assert pulls_requests == 1


@pytest.mark.parametrize(
    ("state", "draft", "merged_at", "events", "expected_merged"),
    [
        pytest.param("open", True, None, [], False, id="open-draft"),
        pytest.param(
            "open",
            False,
            None,
            [_issue_event(1, "ready_for_review")],
            False,
            id="open-ready",
        ),
        pytest.param(
            "closed",
            True,
            None,
            [_issue_event(1, "closed")],
            False,
            id="closed-draft-unmerged",
        ),
        pytest.param(
            "closed",
            False,
            None,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
            ],
            False,
            id="closed-ready-unmerged",
        ),
        pytest.param(
            "closed",
            False,
            "2026-09-03T08:00:00Z",
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "merged"),
                _issue_event(3, "closed"),
            ],
            True,
            id="merged",
        ),
    ],
)
def test_find_draft_preserves_exact_remote_lifecycle(
    state: str,
    draft: bool,
    merged_at: str | None,
    events: list[object],
    expected_merged: bool,
) -> None:
    policy = replace(
        _policy(),
        allowed_pr_authors=(TrustedActor("existing-pr-bot", 77, "Bot"),),
    )
    assert policy.allowed_pr_author_by_id(7) is None
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)

    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        state=state,
        draft=draft,
        merged_at=merged_at,
    )
    exact_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_reads
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            exact_reads += 1
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    result = _broker(handler, policy=policy).find_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title="title",
        body="body",
    )

    assert result is not None
    assert result.created is False
    assert result.state == state
    assert result.draft is draft
    assert result.merged is expected_merged
    assert result.base_sha == BASE_SHA
    assert exact_reads == 3


def test_find_draft_rejects_close_reopen_between_lifecycle_observations() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")
    history_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal history_reads
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            # The pull snapshot is open and byte-identical before and after a
            # close/reopen ABA. Only the append-only lifecycle history proves
            # the otherwise invisible authority change.
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            history_reads += 1
            events = (
                []
                if history_reads == 1
                else [
                    _issue_event(1, "closed"),
                    _issue_event(2, "reopened"),
                ]
            )
            return _response(request, events)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="lifecycle changed"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )

    assert history_reads == 2


def test_find_draft_rejects_close_reopen_then_merge_lifecycle() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        state="closed",
        draft=False,
        merged_at="2026-09-03T08:05:00Z",
        closed_at="2026-09-03T08:05:01Z",
    )
    events = [
        _issue_event(1, "ready_for_review"),
        _issue_event(2, "closed"),
        _issue_event(3, "reopened"),
        _issue_event(4, "merged"),
        _issue_event(5, "closed"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    with pytest.raises(
        RemediationRemoteConflictError,
        match="lifecycle is inconsistent or ambiguous",
    ):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


@pytest.mark.parametrize(
    ("state", "merged_at", "closed_at"),
    [
        ("open", None, "2026-09-03T08:00:00Z"),
        ("closed", None, None),
        ("closed", "2026-09-03T08:05:01Z", "2026-09-03T08:05:00Z"),
        ("closed", None, "not-a-timestamp"),
    ],
)
def test_find_draft_rejects_inconsistent_closed_at_lifecycle(
    state: str,
    merged_at: str | None,
    closed_at: str | None,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        state=state,
        draft=False,
        merged_at=merged_at,
        closed_at=closed_at,
    )
    events = (
        [_issue_event(1, "ready_for_review")]
        if state == "open"
        else [
            _issue_event(1, "ready_for_review"),
            *(
                [_issue_event(2, "merged"), _issue_event(3, "closed")]
                if merged_at is not None
                else [_issue_event(2, "closed")]
            ),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="lifecycle"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


@pytest.mark.parametrize(
    ("state", "draft", "merged_at", "events"),
    [
        (
            "closed",
            False,
            None,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
                _issue_event(3, "reopened"),
                _issue_event(4, "closed"),
            ],
        ),
        (
            "open",
            True,
            None,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "convert_to_draft"),
            ],
        ),
        (
            "open",
            False,
            None,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "converted_to_draft"),
                _issue_event(3, "ready_for_review"),
            ],
        ),
        (
            "open",
            True,
            None,
            [_issue_event(1, "ready_for_review")],
        ),
        (
            "closed",
            False,
            "2026-09-03T08:00:00Z",
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
            ],
        ),
    ],
    ids=(
        "reopened-and-reclosed",
        "redrafted",
        "legacy-redraft-spelling",
        "history-state-mismatch",
        "merge-history-mismatch",
    ),
)
def test_find_draft_rejects_modified_or_reopened_lifecycle(
    state: str,
    draft: bool,
    merged_at: str | None,
    events: list[object],
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        state=state,
        draft=draft,
        merged_at=merged_at,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="lifecycle"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


def test_find_draft_rejects_pull_that_changes_during_stable_observation() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    listed = _pull(branch=branch, title="title", body=f"{marker}\nbody")
    changed = {**listed, "draft": False}
    exact_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_reads
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [listed])
        if request.url.path == "/repos/acme/translations/pulls/91":
            exact_reads += 1
            return _response(request, listed if exact_reads == 1 else changed)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, [])
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="changed during"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )

    assert exact_reads == 3


@pytest.mark.parametrize(
    "events",
    [
        [{}],
        [{"id": 1}],
        [{"event": "ready_for_review"}],
        [{"id": True, "event": "ready_for_review"}],
        [{"id": 1, "event": "ready_for_review\nforged"}],
        [_issue_event(1, "labeled"), _issue_event(1, "ready_for_review")],
        [None],
    ],
)
def test_find_draft_fails_closed_on_malformed_lifecycle_history(
    events: list[object],
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="history"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


def test_find_draft_fails_closed_when_lifecycle_history_exceeds_page_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")
    events = [_issue_event(index, "labeled") for index in range(1, 101)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, events)
        raise AssertionError(request.url)

    monkeypatch.setattr(remediation_module, "_MAX_PULL_EVENT_PAGES", 1)
    with pytest.raises(RemediationRemoteConflictError, match="pagination"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


@pytest.mark.parametrize("failure", ["http", "network"])
def test_lifecycle_history_transport_failures_are_not_remote_conflicts(
    failure: str,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            if failure == "network":
                raise httpx.ConnectError("offline", request=request)
            return _response(request, {"message": "unavailable"}, status=500)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRuntimeError) as raised:
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )

    assert not isinstance(raised.value, RemediationRemoteConflictError)


def test_lifecycle_history_authentication_failure_is_not_remote_conflict() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(request, {"message": "forbidden"}, status=403)
        raise AssertionError(request.url)

    with pytest.raises(GitHubAuthenticationError) as raised:
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )

    assert not isinstance(raised.value, RemediationRemoteConflictError)


def test_find_draft_returns_none_only_for_an_empty_exact_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [])
        raise AssertionError(request.url)

    assert (
        _broker(handler).find_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title="title",
            body="body",
        )
        is None
    )


@pytest.mark.parametrize(
    "payload",
    [{}, [None]],
    ids=["not-a-list", "non-object-member"],
)
def test_find_draft_classifies_malformed_pull_list_as_remote_conflict(
    payload: object,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, payload)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="malformed.*list"):
        _broker(handler).find_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title="title",
            body="body",
        )


def test_find_draft_classifies_malformed_pull_metadata_as_remote_conflict() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")
    pull["draft"] = "true"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="malformed"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body="body",
        )


@pytest.mark.parametrize("failure", ["http", "network"])
def test_find_draft_does_not_misclassify_transport_failures_as_conflicts(
    failure: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            if failure == "network":
                raise httpx.ConnectError("offline", request=request)
            return _response(request, {"message": "unavailable"}, status=500)
        raise AssertionError(request.url)

    with pytest.raises(RemediationRuntimeError) as raised:
        _broker(handler).find_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title="title",
            body="body",
        )

    assert not isinstance(raised.value, RemediationRemoteConflictError)


def test_find_draft_does_not_misclassify_authentication_failure_as_conflict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, {"message": "forbidden"}, status=403)
        raise AssertionError(request.url)

    with pytest.raises(GitHubAuthenticationError) as raised:
        _broker(handler).find_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title="title",
            body="body",
        )

    assert not isinstance(raised.value, RemediationRemoteConflictError)


@pytest.mark.parametrize(
    "headers",
    [
        {"Retry-After": "60"},
        {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1788422400",
        },
    ],
    ids=("retry-after", "primary-rate-limit"),
)
def test_find_draft_classifies_rate_limited_403_as_runtime_failure(
    headers: dict[str, str],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return httpx.Response(
                403,
                request=request,
                headers=headers,
                json={"message": "rate limit exceeded"},
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRuntimeError, match="rate limited") as raised:
        _broker(handler).find_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title="title",
            body="body",
        )

    assert not isinstance(raised.value, GitHubAuthenticationError)
    assert not isinstance(raised.value, RemediationRemoteConflictError)


@pytest.mark.parametrize("actor_id", ["7", 7.0, True, None])
def test_authenticated_actor_id_must_be_a_native_positive_integer(
    actor_id: object,
) -> None:
    broker = _broker(
        lambda request: pytest.fail(f"unexpected request: {request.url}"),
        actor={"login": "translator", "id": actor_id, "type": "User"},
    )

    with pytest.raises(RemediationRuntimeError, match="actor id"):
        broker.capture_base()


@pytest.mark.parametrize(
    "actor",
    [
        {"login": "other-maintainer", "id": 10, "type": "User"},
        {"login": "translator[bot]", "id": 7, "type": "Bot"},
    ],
)
def test_authenticated_actor_must_match_the_single_user_publication_actor(
    actor: dict[str, object],
) -> None:
    other = TrustedActor("other-maintainer", 10, "User")
    policy = replace(
        _policy(),
        allowed_pr_authors=(*_policy().allowed_pr_authors, other),
    )
    broker = _broker(
        lambda request: pytest.fail(f"unexpected request: {request.url}"),
        policy=policy,
        actor=actor,
    )

    with pytest.raises(GitHubAuthenticationError, match="not allowed"):
        broker.capture_base()


def test_shared_snapshot_binds_validated_rest_actor_to_git_push_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuances = iter(("publication-actor-token", "different-actor-token"))
    reads = 0
    authorizations: list[str | None] = []

    def read_secret(_command: SecretCommand) -> str:
        nonlocal reads
        reads += 1
        return next(issuances)

    def handler(request: httpx.Request) -> httpx.Response:
        authorizations.append(request.headers.get("Authorization"))
        if request.url.path == "/user":
            return _response(
                request,
                {"login": "translator", "id": 7, "type": "User"},
            )
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        raise AssertionError(request.url)

    monkeypatch.setattr(SecretCommand, "read", read_secret)
    command = SecretCommand(("helper",))
    with credential_snapshot(command) as credential:
        broker = RemediationGitHubBroker(
            policy=_policy(),
            credential=credential,
            github_host="github.test",
            base_url="https://api.github.test",
            transport=httpx.MockTransport(handler),
        )
        broker.capture_base()
        with git_credential_environment(
            credential,
            temporary_root=tmp_path,
        ) as git_environment:
            push_token = git_environment()["LOCALIZE_GUARDIAN_GIT_TOKEN"]

    assert reads == 1
    assert push_token == "publication-actor-token"
    assert set(authorizations) == {"Bearer publication-actor-token"}


def test_recovered_draft_author_must_equal_the_authenticated_actor() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    other = TrustedActor("other-maintainer", 10, "User")
    policy = replace(
        _policy(),
        allowed_pr_authors=(*_policy().allowed_pr_authors, other),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(
                request,
                [
                    _pull(
                        branch=branch,
                        title="Human review",
                        body=f"{marker}\nHuman review only.",
                        author={
                            "login": other.login,
                            "id": other.id,
                            "type": other.type,
                        },
                    )
                ],
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="exact policy"):
        _broker(handler, policy=policy).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Human review",
            body="Human review only.",
        )


def test_created_draft_author_must_equal_the_authenticated_actor() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    other = TrustedActor("other-maintainer", 10, "User")
    policy = replace(
        _policy(),
        allowed_pr_authors=(*_policy().allowed_pr_authors, other),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        if path == f"/repos/translator/translations/branches/{branch}":
            return _response(request, _branch(branch, CANDIDATE_SHA))
        if path == "/repos/acme/translations/pulls" and request.method == "GET":
            return _response(request, [])
        if path == "/repos/acme/translations/pulls" and request.method == "POST":
            payload = json.loads(request.content)
            return _response(
                request,
                _pull(
                    branch=branch,
                    title=payload["title"],
                    body=payload["body"],
                    author={
                        "login": other.login,
                        "id": other.id,
                        "type": other.type,
                    },
                ),
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="exact policy"):
        _broker(handler, policy=policy).open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Human review",
            body="Human review only.",
            before_create=lambda: None,
            before_post=lambda: None,
        )


@pytest.mark.parametrize(
    ("returned_title", "returned_body"),
    [
        ("Altered title", None),
        (None, "Altered body"),
        (None, "body with the idempotency marker removed"),
    ],
)
def test_recovered_draft_requires_exact_title_and_body_bytes(
    returned_title: str | None,
    returned_body: str | None,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    expected_title = "Human review"
    expected_body = f"{marker}\nHuman review only."

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(
                request,
                [
                    _pull(
                        branch=branch,
                        title=returned_title or expected_title,
                        body=(
                            expected_body if returned_body is None else returned_body
                        ),
                    )
                ],
            )
        raise AssertionError(request.url)

    with pytest.raises(RemediationRemoteConflictError, match="exact policy"):
        _broker(handler).find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=expected_title,
            body="Human review only.",
        )


def test_github_responses_are_streamed_under_a_hard_decoded_byte_cap() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/acme/translations"
        return httpx.Response(
            200,
            request=request,
            content=b"[" + (b" " * (4 * 1024 * 1024)) + b"]",
        )

    with pytest.raises(RemediationRuntimeError, match="size bound"):
        _broker(handler).capture_base()


@pytest.mark.parametrize(
    ("title", "body"),
    [
        ("x" * 257, "body"),
        ("title", "x" * (64 * 1024)),
    ],
)
def test_rejects_oversized_draft_title_and_body_before_network(
    title: str,
    body: str,
) -> None:
    broker = _broker(lambda request: pytest.fail(f"unexpected request: {request.url}"))

    with pytest.raises(ValueError, match="title|body"):
        broker.open_draft(
            branch="translation-updates-history-candidate",
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="c" * 64,
            title=title,
            body=body,
            before_create=lambda: pytest.fail("must reject before mutation"),
            before_post=lambda: pytest.fail("must reject before mutation"),
        )


def test_opens_exact_human_review_draft_after_two_final_rechecks() -> None:
    policy = replace(
        _policy(),
        allowed_pr_authors=(TrustedActor("existing-pr-bot", 77, "Bot"),),
    )
    assert policy.allowed_pr_author_by_id(7) is None
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    post_payloads: list[dict[str, object]] = []
    lease_checks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        if path == f"/repos/translator/translations/branches/{branch}":
            return _response(request, _branch(branch, CANDIDATE_SHA))
        if path == "/repos/acme/translations/pulls" and request.method == "GET":
            return _response(request, [])
        if path == "/repos/acme/translations/pulls" and request.method == "POST":
            payload = json.loads(request.content)
            post_payloads.append(payload)
            return _response(
                request,
                _pull(
                    branch=branch,
                    title=payload["title"],
                    body=payload["body"],
                ),
            )
        raise AssertionError(request.url)

    result = _broker(handler, policy=policy).open_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title="[Localize Guardian] Repair historical translation feedback",
        body="Bot-generated draft for human review.\n",
        before_create=lambda: lease_checks.append("checked"),
        before_post=lambda: lease_checks.append("final"),
    )

    assert result == RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=CANDIDATE_SHA,
        created=True,
        pull_id=9_091,
        base_sha=BASE_SHA,
    )
    assert lease_checks == ["checked", "final"]
    assert post_payloads == [
        {
            "title": "[Localize Guardian] Repair historical translation feedback",
            "body": f"{marker}\nBot-generated draft for human review.\n",
            "head": f"translator:{branch}",
            "head_repo": "translations",
            "base": "main",
            "draft": True,
            "maintainer_can_modify": False,
        }
    ]


def test_draft_post_stops_when_last_exact_source_check_fails() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    sequence: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            sequence.append("post")
            raise AssertionError("POST must not follow a failed exact-source check")
        path = request.url.path
        sequence.append(path)
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        if path == f"/repos/translator/translations/branches/{branch}":
            return _response(request, _branch(branch, CANDIDATE_SHA))
        if path == "/repos/acme/translations/pulls":
            return _response(request, [])
        raise AssertionError(request.url)

    def reject_stale_source() -> None:
        sequence.append("final-source-check")
        raise RemediationRemoteConflictError("historical source moved")

    with pytest.raises(RemediationRemoteConflictError, match="source moved"):
        _broker(handler).open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Human review",
            body="Human review only.",
            before_create=lambda: sequence.append("slow-authority-check"),
            before_post=reject_stale_source,
        )

    assert sequence[-1] == "final-source-check"
    assert "post" not in sequence


def test_draft_post_revalidates_branch_after_slow_source_preparation() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    branch_sha = CANDIDATE_SHA
    posts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal branch_sha
        path = request.url.path
        if request.method == "POST":
            posts.append(request)
            raise AssertionError("POST must not follow branch movement")
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", BASE_SHA))
        if path == f"/repos/translator/translations/branches/{branch}":
            return _response(request, _branch(branch, branch_sha))
        if path == "/repos/acme/translations/pulls":
            return _response(request, [])
        raise AssertionError(request.url)

    def move_branch_during_source_preparation() -> None:
        nonlocal branch_sha
        branch_sha = "d" * 40

    with pytest.raises(RemediationRuntimeError, match="exact candidate"):
        _broker(handler).open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Human review",
            body="Human review only.",
            before_create=move_branch_during_source_preparation,
            before_post=lambda: pytest.fail(
                "final source check must follow destination revalidation"
            ),
        )

    assert posts == []


def test_recovers_exact_closed_draft_after_base_moves_without_posting() -> None:
    evidence_hash = "d" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    posts: list[httpx.Request] = []
    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        base_sha="e" * 40,
        state="closed",
        draft=False,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request)
            raise AssertionError("existing remediation must not be recreated")
        path = request.url.path
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if path == "/repos/acme/translations/issues/91/events":
            return _response(
                request,
                [
                    _issue_event(1, "ready_for_review"),
                    _issue_event(2, "closed"),
                ],
            )
        raise AssertionError(request.url)

    result = _broker(handler).open_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title="title",
        body="body",
        before_create=lambda: pytest.fail("must not consume a creation lease"),
        before_post=lambda: pytest.fail("must not consume a creation lease"),
    )

    assert result.created is False
    assert result.number == 91
    assert result.state == "closed"
    assert result.merged is False
    assert result.draft is False
    assert result.base_sha == "e" * 40
    assert posts == []


def test_recovered_draft_reports_validated_merged_lifecycle() -> None:
    evidence_hash = "d" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(
        branch=branch,
        title="title",
        body=f"{marker}\nbody",
        state="closed",
        draft=False,
        merged_at="2026-09-03T08:00:00Z",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if request.url.path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if request.url.path == "/repos/acme/translations/pulls":
            return _response(request, [pull])
        if request.url.path == "/repos/acme/translations/pulls/91":
            return _response(request, pull)
        if request.url.path == "/repos/acme/translations/issues/91/events":
            return _response(
                request,
                [
                    _issue_event(1, "ready_for_review"),
                    _issue_event(2, "merged"),
                    _issue_event(3, "closed"),
                ],
            )
        raise AssertionError(request.url)

    result = _broker(handler).find_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title="title",
        body="body",
    )

    assert result is not None
    assert result.state == "closed"
    assert result.merged is True
    assert result.draft is False
    assert result.base_sha == BASE_SHA


def test_pull_lifecycle_metadata_is_required_and_well_formed() -> None:
    evidence_hash = "d" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull(branch=branch, title="title", body=f"{marker}\nbody")
    pull.pop("merged_at")
    broker = _broker(lambda request: pytest.fail(str(request.url)))

    with pytest.raises(RemediationRemoteConflictError, match="lifecycle"):
        broker._validated_pull(  # noqa: SLF001 - response boundary regression
            pull,
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            marker=marker,
            expected_author=(7, "User"),
            expected_title="title",
            expected_body=f"{marker}\nbody",
            require_new_draft=False,
        )


@pytest.mark.parametrize("require_new_draft", [False, True])
def test_pull_response_requires_maintainer_changes_disabled(
    require_new_draft: bool,
) -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    broker = _broker(lambda request: pytest.fail(str(request.url)))

    with pytest.raises(RemediationRemoteConflictError, match="metadata|exact policy"):
        broker._validated_pull(  # noqa: SLF001 - response boundary regression
            _pull(
                branch=branch,
                title="title",
                body=f"{marker}\nbody",
                maintainer_can_modify=True,
            ),
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            marker=marker,
            expected_author=(7, "User"),
            expected_title="title",
            expected_body=f"{marker}\nbody",
            require_new_draft=require_new_draft,
        )


def test_fresh_post_response_must_be_open_and_draft() -> None:
    evidence_hash = "c" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    broker = _broker(lambda request: pytest.fail(str(request.url)))

    with pytest.raises(RemediationRemoteConflictError, match="draft"):
        broker._validated_pull(  # noqa: SLF001 - response boundary regression
            _pull(
                branch=branch,
                title="title",
                body=f"{marker}\nbody",
                state="closed",
            ),
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            marker=marker,
            expected_author=(7, "User"),
            expected_title="title",
            expected_body=f"{marker}\nbody",
            require_new_draft=True,
        )


def test_refuses_creation_when_current_base_moved() -> None:
    evidence_hash = "e" * 64
    branch = f"translation-updates-history-{evidence_hash[:20]}"
    marker = RemediationGitHubBroker.marker(evidence_hash, CANDIDATE_SHA)
    posts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request)
        path = request.url.path
        if path == "/repos/acme/translations":
            return _response(request, _repo("acme/translations", 42))
        if path == "/repos/translator/translations":
            return _response(request, _repo("translator/translations", 84))
        if path == "/repos/acme/translations/pulls":
            return _response(request, [])
        if path == "/repos/acme/translations/branches/main":
            return _response(request, _branch("main", "f" * 40))
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    with pytest.raises(RemediationRuntimeError, match="base moved"):
        _broker(handler).open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="title",
            body=f"{marker}\nbody",
            before_create=lambda: None,
            before_post=lambda: None,
        )
    assert posts == []


def test_policy_without_explicit_remediation_authority_is_rejected() -> None:
    policy = replace(
        _policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=120,
            max_prs_per_poll=4,
        ),
    )
    with pytest.raises(ValueError, match="remediation policy"):
        RemediationGitHubBroker(
            policy=policy,
            token_command=("gh", "auth", "token"),
        )


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
FEEDBACK_URLS = (
    "https://github.test/acme/translations/pull/12#discussion_r100",
    "https://github.test/acme/translations/issues/13#issuecomment-200",
)


def _base_snapshot(*, sha: str = BASE_SHA, private: bool = False) -> Any:
    from localize.guardian.remediation import RemediationBaseSnapshot

    return RemediationBaseSnapshot(
        revision=ExactRevision(
            host="github.test",
            owner="acme",
            repository="translations",
            ref="refs/heads/main",
            sha=sha,
        ),
        target_repository_id=42,
        push_repository_id=84,
        private=private,
    )


def _source_pulls() -> tuple[HistoricalPullReference, ...]:
    return (
        HistoricalPullReference(
            repository="acme/translations",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            policy_digest="2" * 64,
            authority_digest="5" * 64,
            head_sha="1" * 40,
            base_sha="2" * 40,
        ),
        HistoricalPullReference(
            repository="acme/translations",
            repository_id=42,
            pull_id=501,
            pr_number=13,
            pull_revision_digest="3" * 64,
            policy_digest="2" * 64,
            authority_digest="5" * 64,
            head_sha="3" * 40,
            base_sha="4" * 40,
        ),
    )


def _replacements() -> tuple[ProposedReplacement, ...]:
    return (
        ProposedReplacement(
            feedback_id="review_comment:100",
            path="l10n/messages_ru.properties",
            key="first.key",
            locale="ru",
            expected_value="old one",
            proposed_value="new one",
            confidence=0.99,
            evidence=("native reviewer",),
            source_value="First",
        ),
        ProposedReplacement(
            feedback_id="issue_comment:200",
            path="l10n/messages_ru.properties",
            key="second.key",
            locale="ru",
            expected_value="old two",
            proposed_value="new two",
            confidence=0.98,
            evidence=("review bot",),
            source_value="Second",
        ),
    )


def _patch() -> PatchResult:
    return PatchResult(
        changed_files=("l10n/messages_ru.properties",),
        changed_keys=(
            ("l10n/messages_ru.properties", "first.key"),
            ("l10n/messages_ru.properties", "second.key"),
        ),
    )


class _StateSpy:
    def __init__(
        self,
        *,
        pending: tuple[RemediationDraftRecord, ...] = (),
        opened: tuple[RemediationDraftRecord, ...] = (),
        order: list[str] | None = None,
        current_evidence_valid: bool = True,
        successor_intents: dict[str, RemediationSuccessorIntent] | None = None,
        successor_publications: (
            dict[str, tuple[RemediationSuccessorPublication, ...]] | None
        ) = None,
    ) -> None:
        self.pending = pending
        self.opened = opened
        self.order = order if order is not None else []
        self.current_evidence_valid = current_evidence_valid
        self.events: list[dict[str, object]] = []
        self.checkpoints: list[dict[str, object]] = []
        self.checkpointed_drafts: set[str] = set()
        self.recovery_attempts: dict[str, int] = {}
        self.recovery_attempt_counter = 0
        self.resolutions: dict[str, str] = {}
        self.completed_sources: set[tuple[object, ...]] = set()
        self.remote_observations: list[dict[str, object]] = []
        self.merged_revalidations: list[MergedRemediationRevalidation] = []
        self.merge_revalidation_attempts: list[str] = []
        self.merge_revalidation_outcomes: dict[str, str] = {}
        self._validated_sources: tuple[HistoricalPullReference, ...] = ()
        self.successor_intents = successor_intents or {}
        self.successor_publications = successor_publications or {}

    def validate_historical_remediation_evidence(
        self,
        **kwargs: object,
    ) -> str:
        from localize.guardian.remediation import _evidence_hash

        self.order.append("state:evidence-validated")
        self._validated_sources = tuple(kwargs["source_pulls"])  # type: ignore[arg-type]
        return _evidence_hash(
            kwargs["source_pulls"],
            kwargs.get("feedback_urls", tuple(sorted(FEEDBACK_URLS))),
        )

    def validate_current_historical_remediation_evidence(
        self,
        **kwargs: object,
    ) -> str:
        self.order.append("state:current-evidence-validated")
        if not self.current_evidence_valid:
            raise ValueError("superseded evidence")
        return self.validate_historical_remediation_evidence(**kwargs)

    def record_remediation_draft_event(self, **kwargs: object) -> str:
        self.events.append(dict(kwargs))
        self.order.append(f"state:{kwargs['phase']}")
        if kwargs["phase"] == "abandoned":
            for record in (*self.pending, *self.opened):
                if record.branch == kwargs["branch"]:
                    self.resolutions[record.draft_key] = "abandoned"
        return "draft-key"

    def pending_remediation_drafts(
        self,
        *,
        repository: str | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        return tuple(
            record
            for record in self.pending
            if repository is None or record.target_repository == repository
        )

    def active_remediation_drafts_for_identity(
        self,
        *,
        repository: str,
        repository_id: int,
        batch_hash: str,
    ) -> tuple[RemediationDraftRecord, ...]:
        return tuple(
            record
            for record in (*self.pending, *self.opened)
            if record.draft_key not in self.resolutions
            if record.target_repository == repository
            and record.target_repository_id == repository_id
            and record.batch_hash == batch_hash
            and record.phase in {"validated", "pushed", "draft_opened"}
        )

    def remediation_edit_coverage(
        self,
        *,
        target_repository: str,
        target_repository_id: int,
        edit_target_hashes: tuple[tuple[str, str], ...],
    ) -> RemediationEditCoverage:
        requested = dict(edit_target_hashes)
        target_to_edit = {
            target_hash: edit_hash for edit_hash, target_hash in edit_target_hashes
        }
        opened: set[str] = set()
        pending: set[str] = set()
        incompatible: set[str] = set()
        conflicting: set[str] = set()
        identity_conflict = False
        for record in (*self.pending, *self.opened):
            if record.draft_key in self.resolutions:
                continue
            if record.phase not in {"validated", "pushed", "draft_opened"}:
                continue
            if (
                record.target_repository.casefold() == target_repository.casefold()
                or record.target_repository_id == target_repository_id
            ) and (
                record.target_repository != target_repository
                or record.target_repository_id != target_repository_id
            ):
                identity_conflict = True
            if (
                record.target_repository == target_repository
                and record.target_repository_id == target_repository_id
            ):
                for active_edit, active_target in record.edit_target_hashes:
                    requested_edit = target_to_edit.get(active_target)
                    if requested_edit is not None and requested_edit != active_edit:
                        conflicting.add(requested_edit)
            overlap = set(requested).intersection(record.edit_hashes)
            if not overlap:
                continue
            if (
                record.target_repository != target_repository
                or record.target_repository_id != target_repository_id
            ):
                if (
                    record.target_repository.casefold() == target_repository.casefold()
                    or record.target_repository_id == target_repository_id
                ):
                    incompatible.update(overlap)
            elif record.phase == "draft_opened":
                opened.update(overlap)
            else:
                pending.update(overlap)
        return RemediationEditCoverage(
            opened_edit_hashes=frozenset(opened),
            pending_edit_hashes=frozenset(pending),
            incompatible_edit_hashes=frozenset(incompatible),
            conflicting_edit_hashes=frozenset(conflicting),
            repository_identity_conflict=identity_conflict,
        )

    def pending_remediation_drafts_for_recovery(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        pending = self.pending_remediation_drafts(repository=repository)
        return tuple(
            sorted(
                (
                    record
                    for record in pending
                    if repository_id is None
                    or record.target_repository_id == repository_id
                ),
                key=lambda record: self.recovery_attempts.get(record.draft_key, 0),
            )[:limit]
        )

    def record_remediation_recovery_attempt(self, **kwargs: object) -> None:
        self.recovery_attempt_counter += 1
        self.recovery_attempts[str(kwargs["draft_key"])] = self.recovery_attempt_counter

    def opened_remediation_drafts(
        self,
        *,
        repository: str | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        return tuple(
            record
            for record in self.opened
            if record.draft_key not in self.resolutions
            if repository is None or record.target_repository == repository
        )

    def opened_remediation_drafts_for_reconciliation(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        return tuple(
            sorted(
                (
                    record
                    for record in self.opened_remediation_drafts(repository=repository)
                    if repository_id is None
                    or record.target_repository_id == repository_id
                ),
                key=lambda record: self.recovery_attempts.get(record.draft_key, 0),
            )[:limit]
        )

    def pending_merged_remediation_revalidations(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[MergedRemediationRevalidation, ...]:
        return tuple(
            item
            for item in self.merged_revalidations
            if item.revalidation_key not in self.merge_revalidation_outcomes
            if repository is None or item.source.repository == repository
            if repository_id is None or item.source.repository_id == repository_id
        )[:limit]

    def record_merged_remediation_revalidation_attempt(
        self,
        **_kwargs: object,
    ) -> MergedRemediationRevalidation:
        key = str(_kwargs["revalidation_key"])
        self.merge_revalidation_attempts.append(key)
        return next(
            item for item in self.merged_revalidations if item.revalidation_key == key
        )

    def resolve_merged_remediation_revalidation(
        self,
        **_kwargs: object,
    ) -> MergedRemediationRevalidation:
        key = str(_kwargs["revalidation_key"])
        self.merge_revalidation_outcomes[key] = str(_kwargs["outcome"])
        return next(
            item for item in self.merged_revalidations if item.revalidation_key == key
        )

    def record_remediation_resolution(self, **kwargs: object) -> bool:
        draft_key = str(kwargs["draft_key"])
        resolution = str(kwargs["resolution"])
        if draft_key in self.resolutions:
            return False
        self.resolutions[draft_key] = resolution
        return True

    def uncheckpointed_opened_remediation_drafts(
        self,
        *,
        repository: str | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        return tuple(
            record
            for record in self.opened_remediation_drafts(repository=repository)
            if record.draft_key not in self.checkpointed_drafts
        )[:limit]

    def record_remediation_checkpoint(self, **kwargs: object) -> bool:
        draft_key = str(kwargs["draft_key"])
        is_new = draft_key not in self.checkpointed_drafts
        self.checkpointed_drafts.add(draft_key)
        return is_new

    def record_historical_pull_completion(self, **kwargs: object) -> bool:
        self.checkpoints.append(dict(kwargs))
        self.order.append(f"checkpoint:{kwargs['pr_number']}")
        return True

    @staticmethod
    def _completion_identity(source: HistoricalPullReference) -> tuple[object, ...]:
        return (
            source.repository,
            source.repository_id,
            source.pull_id,
            source.pull_revision_digest,
            source.policy_digest,
        )

    def historical_pull_is_complete(self, **kwargs: object) -> bool:
        identity = (
            kwargs["repository"],
            kwargs["repository_id"],
            kwargs["pull_id"],
            kwargs["pull_revision_digest"],
            kwargs["policy_digest"],
        )
        return identity in self.completed_sources

    def get_event_revision(self, revision_id: int) -> object | None:
        revision_ids = (101, 102)
        if revision_id not in revision_ids or not self._validated_sources:
            return None
        index = revision_ids.index(revision_id)
        if index >= len(self._validated_sources):
            return None
        source = self._validated_sources[index]
        return type(
            "EventRevisionStub",
            (),
            {"repository": source.repository, "pr_number": source.pr_number},
        )()

    def record_draft_backed_remediation_completions(
        self,
        coverage_by_source: object,
        reason: object,
        **kwargs: object,
    ) -> tuple[object, ...]:
        assert isinstance(coverage_by_source, dict)
        for source, draft_keys in coverage_by_source.items():
            assert isinstance(source, HistoricalPullReference)
            self.completed_sources.add(self._completion_identity(source))
            self.checkpoints.append(
                {
                    "repository": source.repository,
                    "repository_id": source.repository_id,
                    "pull_id": source.pull_id,
                    "pr_number": source.pr_number,
                    "pull_revision_digest": source.pull_revision_digest,
                    "policy_digest": source.policy_digest,
                    "authority_scope": HistoricalCheckScope.REMEDIATION,
                    "reason": reason,
                    "draft_keys": tuple(draft_keys),
                }
            )
            self.order.append(f"checkpoint:{source.pr_number}")
        checkpoint = kwargs.get("checkpoint_draft_key")
        if isinstance(checkpoint, str):
            self.checkpointed_drafts.add(checkpoint)
        return tuple(object() for _source in coverage_by_source)

    def record_remediation_remote_observation(self, **kwargs: object) -> object:
        self.remote_observations.append(dict(kwargs))
        if kwargs.get("observation") == "exact" and kwargs.get("is_merged") is True:
            self.resolutions[str(kwargs["draft_key"])] = "merged"
        return object()

    def remediation_draft_by_key(
        self,
        *,
        draft_key: str,
    ) -> RemediationDraftRecord | None:
        return next(
            (
                record
                for record in (*self.pending, *self.opened)
                if record.draft_key == draft_key
            ),
            None,
        )

    def remediation_successor_intent(
        self,
        *,
        publication_key: str,
    ) -> RemediationSuccessorIntent | None:
        return self.successor_intents.get(publication_key)

    def remediation_successor_publications(
        self,
        *,
        draft_key: str,
    ) -> tuple[RemediationSuccessorPublication, ...]:
        return self.successor_publications.get(draft_key, ())

    def remediation_candidate_tip(self, draft_key: str) -> str:
        successors = self.successor_publications.get(draft_key, ())
        if successors:
            return successors[-1].successor_candidate_sha
        for record in (*self.pending, *self.opened):
            if record.draft_key == draft_key:
                return record.candidate_sha
        for event in self.events:
            if event.get("draft_key") == draft_key:
                return str(event["candidate_sha"])
        raise ValueError("Unknown remediation draft key.")

    def require_exact_sources_still_closed(
        self,
        _sources: object,
        _revision_ids: object,
    ) -> None:
        self.order.append("sources")


class _BrokerSpy:
    def __init__(
        self,
        base: Any,
        *,
        order: list[str],
        branches: dict[str, str | None] | None = None,
        existing: dict[str, RemediationDraftResult] | None = None,
    ) -> None:
        self.base = base
        self.order = order
        self.branches = branches if branches is not None else {}
        self.existing = existing if existing is not None else {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def capture_base(self) -> Any:
        self.calls.append(("capture_base", {}))
        return self.base

    def verify_publish_authority(self, **kwargs: object) -> None:
        self.calls.append(("verify_publish_authority", dict(kwargs)))

    def branch_sha(self, branch: str) -> str | None:
        self.calls.append(("branch_sha", {"branch": branch}))
        return self.branches.get(branch)

    def find_draft(self, **kwargs: object) -> RemediationDraftResult | None:
        self.calls.append(("find_draft", dict(kwargs)))
        existing = self.existing.get(str(kwargs["branch"]))
        if existing is not None and existing.base_sha is None:
            object.__setattr__(
                existing,
                "base_sha",
                str(kwargs["expected_base_sha"]),
            )
        return existing

    def open_draft(
        self,
        *,
        before_create,
        before_post=None,
        **kwargs: object,
    ) -> RemediationDraftResult:
        self.calls.append(("open_draft", dict(kwargs)))
        existing = self.existing.get(str(kwargs["branch"]))
        if existing is not None:
            if existing.base_sha is None:
                object.__setattr__(
                    existing,
                    "base_sha",
                    str(kwargs["expected_base_sha"]),
                )
            return existing
        before_create()
        if before_post is not None:
            before_post()
        self.order.append("remote:draft-post")
        return RemediationDraftResult(
            number=91,
            html_url="https://github.test/acme/translations/pull/91",
            candidate_sha=str(kwargs["candidate_sha"]),
            created=True,
            pull_id=9_091,
            base_sha=str(kwargs["expected_base_sha"]),
        )


class _WorkspaceSpy:
    def __init__(
        self,
        base: Any,
        *,
        order: list[str],
        fail_after_push_slot: bool = False,
    ) -> None:
        self.revision = base.revision
        self.original_sha = base.revision.sha
        self.order = order
        self.fail_after_push_slot = fail_after_push_slot
        self.commit_calls: list[dict[str, object]] = []
        self.publish_calls: list[dict[str, object]] = []

    def commit_historical_remediation_changes(self, **kwargs: object) -> CommitResult:
        self.commit_calls.append(dict(kwargs))
        self.order.append("workspace:commit")
        return CommitResult(
            commit_sha=CANDIDATE_SHA,
            parent_sha=self.original_sha,
            changed_paths=tuple(kwargs["expected_paths"]),
            signature_verified=True,
        )

    def publish_remediation_branch(
        self,
        commit: CommitResult,
        *,
        before_push,
        **kwargs: object,
    ) -> PreventionPublicationResult:
        self.publish_calls.append({"commit": commit, **kwargs})
        before_push()
        self.order.append("remote:branch-push")
        if self.fail_after_push_slot:
            raise RuntimeError("lost push response")
        return PreventionPublicationResult(
            repository=str(kwargs["push_repository"]),
            ref=f"refs/heads/{kwargs['branch']}",
            commit_sha=commit.commit_sha,
            created=True,
        )


def _record(
    *,
    phase: str,
    base_sha: str = BASE_SHA,
    candidate_sha: str = CANDIDATE_SHA,
    batch_hash: str = "d" * 64,
    branch_identity_version: int = 2,
    policy_digest: str = "2" * 64,
) -> RemediationDraftRecord:
    from localize.guardian.remediation import _branch_name, _evidence_hash

    source_pulls = tuple(
        replace(source, policy_digest=policy_digest) for source in _source_pulls()
    )
    evidence_hash = _evidence_hash(source_pulls, tuple(sorted(FEEDBACK_URLS)))
    edit_hashes = tuple(sorted(remediation_edit_hash(item) for item in _replacements()))
    edit_target_hashes = tuple(
        sorted(
            (remediation_edit_hash(item), remediation_target_hash(item))
            for item in _replacements()
        )
    )
    if batch_hash == "d" * 64:
        batch_hash = remediation_batch_hash(edit_hashes)
    branch = _branch_name(
        prefix="translation-updates-history-",
        batch_hash=batch_hash,
        target_base_sha=base_sha,
        evidence_hash=evidence_hash,
        branch_identity_version=branch_identity_version,
        policy_digests=(policy_digest,),
    )
    return RemediationDraftRecord(
        draft_key=batch_hash,
        branch_identity_version=branch_identity_version,
        run_id="run-1",
        target_repository="acme/translations",
        target_repository_id=42,
        target_base_branch="main",
        target_base_sha=base_sha,
        push_repository="translator/translations",
        push_repository_id=84,
        branch=branch,
        candidate_sha=candidate_sha,
        evidence_hash=evidence_hash,
        batch_hash=batch_hash,
        edit_hashes=edit_hashes,
        edit_target_hashes=edit_target_hashes,
        source_pulls=source_pulls,
        event_revision_ids=(101, 102),
        changed_paths=("l10n/messages_ru.properties",),
        title="[Localize Guardian bot] Historical translation corrections",
        body="Bot-generated draft for human review only.\n",
        phase=phase,
        draft_number=91 if phase == "draft_opened" else None,
        draft_pull_id=9_091 if phase == "draft_opened" else None,
        draft_url=(
            "https://github.test/acme/translations/pull/91"
            if phase == "draft_opened"
            else None
        ),
        occurred_at=NOW,
    )


def test_recovery_path_policy_does_not_let_star_cross_nested_segments() -> None:
    nested = replace(
        _record(phase="pushed"),
        changed_paths=("l10n/nested/messages_ru.properties",),
    )
    shallow_policy = _policy()

    assert not remediation_module.RemediationCoordinator._record_matches_policy(
        nested,
        shallow_policy,
    )
    assert remediation_module.RemediationCoordinator._record_matches_policy(
        nested,
        replace(shallow_policy, allowed_path_globs=("l10n/**/*.properties",)),
    )


def test_recovery_routes_renamed_repositories_by_immutable_ids() -> None:
    record = _record(phase="draft_opened")
    current = _policy()
    remediation = current.closed_pr_backfill.remediation
    assert remediation is not None
    renamed = replace(
        current,
        base_repo="acme/renamed-translations",
        allowed_head_repositories=(
            AllowedHeadRepository("translator/renamed-translations", 84),
        ),
        closed_pr_backfill=replace(
            current.closed_pr_backfill,
            remediation=replace(
                remediation,
                push_repository=ExactRepository(
                    "translator/renamed-translations",
                    remediation.push_repository.id,
                ),
            ),
        ),
    )

    assert RemediationCoordinator._record_matches_policy(record, renamed)
    routed = remediation_module._opened_pull_identity(record, policy=renamed)
    assert routed.repository == "acme/renamed-translations"
    assert routed.repository_id == record.target_repository_id
    assert routed.head_repository == "translator/renamed-translations"
    assert routed.head_repository_id == record.push_repository_id


class _CoordinatorHarness(RemediationCoordinator):
    """Inject the test snapshot provider into recovery calls by default."""

    def recover(self, **kwargs: object) -> RemediationBatchOutcome:
        kwargs.setdefault(
            "require_exact_sources_still_closed",
            self.state.require_exact_sources_still_closed,
        )
        kwargs.setdefault(
            "require_no_open_translation_overlap",
            lambda _paths, _excluded: None,
        )
        return super().recover(**kwargs)  # type: ignore[arg-type]


def _coordinator(
    state: _StateSpy,
    broker: _BrokerSpy,
    *,
    max_drafts: int = 1,
) -> RemediationCoordinator:
    return _CoordinatorHarness(
        state=state,
        broker_factory=lambda policy: broker,
        publish_credential_environment=lambda: {"GIT_ASKPASS": "/safe/helper"},
        signing_key="ABCDEF",
        signing_environment={"GNUPGHOME": "/safe/gnupg"},
        max_drafts=max_drafts,
    )


def _successor_intent(
    record: RemediationDraftRecord,
    *,
    publication_key: str,
    successor_sha: str,
) -> RemediationSuccessorIntent:
    assert record.changed_paths is not None
    return RemediationSuccessorIntent(
        intent_key="7" * 64,
        draft_key=record.draft_key,
        publication_key=publication_key,
        run_id="successor-run",
        parent_candidate_sha=record.candidate_sha,
        successor_candidate_sha=successor_sha,
        source_pulls=record.source_pulls,
        edit_hashes=record.edit_hashes,
        changed_paths=record.changed_paths,
        actor_id=9,
        actor_type="User",
        publication_actor_id=7,
        publication_actor_type="User",
        occurred_at=NOW,
    )


@pytest.mark.parametrize(
    ("boundary", "remote_head_sha"),
    [
        ("immediately before push", CANDIDATE_SHA),
        ("push-crash recovery", "c" * 40),
    ],
)
def test_successor_revalidation_uses_exact_durable_pull_metadata(
    boundary: str,
    remote_head_sha: str,
) -> None:
    publication_key = "6" * 64
    successor_sha = "c" * 40
    record = _record(phase="draft_opened")
    intent = _successor_intent(
        record,
        publication_key=publication_key,
        successor_sha=successor_sha,
    )
    result = RemediationDraftResult(
        number=record.draft_number or 0,
        pull_id=record.draft_pull_id,
        html_url=record.draft_url or "",
        candidate_sha=remote_head_sha,
        created=False,
        base_sha=record.target_base_sha,
    )
    order: list[str] = []
    state = _StateSpy(
        opened=(record,),
        order=order,
        successor_intents={publication_key: intent},
    )
    broker = _BrokerSpy(
        _base_snapshot(),
        order=order,
        existing={record.branch: result},
    )
    overlap_calls: list[tuple[tuple[str, ...], OpenPullPathIdentity | None]] = []

    recovered = _coordinator(state, broker).revalidate_successor_pull(
        policy=_policy(),
        publication_key=publication_key,
        expected_remote_head_sha=remote_head_sha,
        expected_base_sha=record.target_base_sha,
        require_open=True,
        require_live_lease=lambda: order.append("lease"),
        require_no_open_translation_overlap=lambda paths, excluded: (
            overlap_calls.append((tuple(paths), excluded))
        ),
    )

    assert recovered == result, boundary
    assert order == ["lease"] * 6
    assert overlap_calls == [
        (
            intent.changed_paths,
            OpenPullPathIdentity(
                repository=record.target_repository,
                repository_id=record.target_repository_id,
                pull_id=record.draft_pull_id or 0,
                number=record.draft_number or 0,
                head_repository=record.push_repository,
                head_repository_id=record.push_repository_id,
                head_ref=record.branch,
                head_sha=remote_head_sha,
            ),
        )
    ]
    expected_find = (
        "find_draft",
        {
            "branch": record.branch,
            "expected_base_sha": record.target_base_sha,
            "candidate_sha": remote_head_sha,
            "marker_candidate_sha": record.candidate_sha,
            "evidence_hash": record.evidence_hash,
            "title": record.title,
            "body": record.body,
        },
    )
    assert broker.calls == [expected_find, expected_find]


def test_successor_revalidation_rejects_pull_changed_during_overlap_refresh() -> None:
    publication_key = "6" * 64
    record = _record(phase="draft_opened")
    result = RemediationDraftResult(
        number=record.draft_number or 0,
        pull_id=record.draft_pull_id,
        html_url=record.draft_url or "",
        candidate_sha=record.candidate_sha,
        created=False,
        base_sha=record.target_base_sha,
    )
    state = _StateSpy(
        opened=(record,),
        successor_intents={
            publication_key: _successor_intent(
                record,
                publication_key=publication_key,
                successor_sha="c" * 40,
            )
        },
    )
    broker = _BrokerSpy(
        _base_snapshot(),
        order=[],
        existing={record.branch: result},
    )

    def close_during_overlap(
        _paths: Sequence[str],
        _excluded: OpenPullPathIdentity | None,
    ) -> None:
        broker.existing[record.branch] = replace(
            result,
            state="closed",
            draft=False,
            closed_at="2026-09-03T08:00:00Z",
        )

    with pytest.raises(RemediationRemoteConflictError, match="publication authority"):
        _coordinator(state, broker).revalidate_successor_pull(
            policy=_policy(),
            publication_key=publication_key,
            expected_remote_head_sha=record.candidate_sha,
            expected_base_sha=record.target_base_sha,
            require_open=True,
            require_live_lease=lambda: None,
            require_no_open_translation_overlap=close_during_overlap,
        )

    assert [name for name, _kwargs in broker.calls] == [
        "find_draft",
        "find_draft",
    ]


def test_successor_revalidation_rejects_publication_actor_rotation() -> None:
    publication_key = "6" * 64
    record = _record(phase="draft_opened")
    original = _policy()
    rotated_actor = TrustedActor("other-publisher", 17, "User")
    assert original.closed_pr_backfill is not None
    assert original.closed_pr_backfill.remediation is not None
    rotated = replace(
        original,
        allowed_pr_authors=(*original.allowed_pr_authors, rotated_actor),
        closed_pr_backfill=replace(
            original.closed_pr_backfill,
            remediation=replace(
                original.closed_pr_backfill.remediation,
                publication_actor=rotated_actor,
            ),
        ),
    )
    state = _StateSpy(
        opened=(record,),
        successor_intents={
            publication_key: _successor_intent(
                record,
                publication_key=publication_key,
                successor_sha="c" * 40,
            )
        },
    )
    broker = _BrokerSpy(_base_snapshot(), order=[])

    with pytest.raises(RemediationRemoteConflictError, match="actor changed"):
        _coordinator(state, broker).revalidate_successor_pull(
            policy=rotated,
            publication_key=publication_key,
            expected_remote_head_sha=record.candidate_sha,
            expected_base_sha=record.target_base_sha,
            require_open=True,
            require_live_lease=lambda: None,
            require_no_open_translation_overlap=lambda _paths, _excluded: None,
        )

    assert broker.calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: replace(result, number=92),
        lambda result: replace(result, pull_id=9_092),
        lambda result: replace(result, candidate_sha="d" * 40),
        lambda result: replace(result, base_sha="e" * 40),
        lambda result: replace(result, state="closed"),
    ],
    ids=("number", "pull-id", "head", "base", "lifecycle"),
)
def test_successor_revalidation_rejects_changed_remote_authority(
    mutate: Any,
) -> None:
    publication_key = "6" * 64
    record = _record(phase="draft_opened")
    result = RemediationDraftResult(
        number=record.draft_number or 0,
        pull_id=record.draft_pull_id,
        html_url=record.draft_url or "",
        candidate_sha=record.candidate_sha,
        created=False,
        base_sha=record.target_base_sha,
    )
    state = _StateSpy(
        opened=(record,),
        successor_intents={
            publication_key: _successor_intent(
                record,
                publication_key=publication_key,
                successor_sha="c" * 40,
            )
        },
    )
    broker = _BrokerSpy(
        _base_snapshot(),
        order=[],
        existing={record.branch: mutate(result)},
    )

    with pytest.raises(RemediationRemoteConflictError, match="publication authority"):
        _coordinator(state, broker).revalidate_successor_pull(
            policy=_policy(),
            publication_key=publication_key,
            expected_remote_head_sha=record.candidate_sha,
            expected_base_sha=record.target_base_sha,
            require_open=True,
            require_live_lease=lambda: None,
            require_no_open_translation_overlap=lambda _paths, _excluded: None,
        )


def test_successor_revalidation_rejects_a_stale_parent_after_lineage_advances() -> None:
    publication_key = "6" * 64
    successor_sha = "c" * 40
    record = _record(phase="draft_opened")
    intent = _successor_intent(
        record,
        publication_key=publication_key,
        successor_sha=successor_sha,
    )
    publication = RemediationSuccessorPublication(
        lineage_key=intent.intent_key,
        draft_key=intent.draft_key,
        publication_key=intent.publication_key,
        run_id=intent.run_id,
        parent_candidate_sha=intent.parent_candidate_sha,
        successor_candidate_sha=intent.successor_candidate_sha,
        source_pulls=intent.source_pulls,
        edit_hashes=intent.edit_hashes,
        changed_paths=intent.changed_paths,
        actor_id=intent.actor_id,
        actor_type=intent.actor_type,
        publication_actor_id=intent.publication_actor_id,
        publication_actor_type=intent.publication_actor_type,
        occurred_at=NOW,
    )
    state = _StateSpy(
        opened=(record,),
        successor_intents={publication_key: intent},
        successor_publications={record.draft_key: (publication,)},
    )
    broker = _BrokerSpy(
        _base_snapshot(),
        order=[],
        existing={
            record.branch: RemediationDraftResult(
                number=record.draft_number or 0,
                pull_id=record.draft_pull_id,
                html_url=record.draft_url or "",
                candidate_sha=record.candidate_sha,
                created=False,
                base_sha=record.target_base_sha,
            )
        },
    )

    with pytest.raises(RemediationRemoteConflictError, match="current lineage"):
        _coordinator(state, broker).revalidate_successor_pull(
            policy=_policy(),
            publication_key=publication_key,
            expected_remote_head_sha=record.candidate_sha,
            expected_base_sha=record.target_base_sha,
            require_open=True,
            require_live_lease=lambda: None,
            require_no_open_translation_overlap=lambda _paths, _excluded: None,
        )

    assert broker.calls == []


def _publish(
    coordinator: RemediationCoordinator,
    workspace: _WorkspaceSpy,
    base: Any,
    *,
    replacements: tuple[ProposedReplacement, ...] | None = None,
    source_pulls: tuple[HistoricalPullReference, ...] | None = None,
    feedback_urls: tuple[str, ...] | None = None,
    require_live_lease=None,
    require_exact_sources_still_closed=None,
    require_no_open_translation_overlap=None,
    prior_draft_keys_by_source: dict[HistoricalPullReference, tuple[str, ...]]
    | None = None,
    required_edit_hashes_by_source: dict[HistoricalPullReference, tuple[str, ...]]
    | None = None,
) -> RemediationBatchOutcome:
    exact_sources = source_pulls or _source_pulls()
    selected_replacements = replacements or _replacements()
    selected_edit_hashes = tuple(
        sorted(remediation_edit_hash(item) for item in selected_replacements)
    )
    return coordinator.publish(
        policy=_policy(),
        base=base,
        workspace=workspace,
        patch_result=_patch(),
        replacements=selected_replacements,
        source_pulls=exact_sources,
        event_revision_ids=(101, 102),
        feedback_urls=feedback_urls or FEEDBACK_URLS,
        run_id="run-1",
        observed_at=NOW,
        require_live_lease=(
            require_live_lease or (lambda: workspace.order.append("lease"))
        ),
        require_current_base_unchanged=lambda: workspace.order.append("base"),
        require_exact_sources_still_closed=(
            require_exact_sources_still_closed
            or (lambda _sources, _revision_ids: workspace.order.append("sources"))
        ),
        require_no_open_translation_overlap=(
            require_no_open_translation_overlap or (lambda _paths, _excluded: None)
        ),
        prior_draft_keys_by_source=(
            prior_draft_keys_by_source
            if prior_draft_keys_by_source is not None
            else {source: () for source in exact_sources}
        ),
        required_edit_hashes_by_source=(
            required_edit_hashes_by_source
            if required_edit_hashes_by_source is not None
            else {source: selected_edit_hashes for source in exact_sources}
        ),
    )


def test_coordinator_batches_origins_into_one_signed_human_review_draft() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)
    coordinator = _coordinator(state, broker)

    outcome = _publish(coordinator, workspace, base)

    assert isinstance(outcome, RemediationBatchOutcome)
    assert len(outcome.drafts) == 1
    assert outcome.drafts[0].created is True
    assert outcome.deferred == 0
    assert len(workspace.commit_calls) == 1
    commit_call = workspace.commit_calls[0]
    assert commit_call["author_email"] == "7+translator@users.noreply.github.com"
    assert commit_call["feedback_pull_numbers"] == (12, 13)
    assert commit_call["feedback_urls"] == tuple(sorted(FEEDBACK_URLS))
    assert commit_call["signing_key"] == "ABCDEF"
    assert commit_call["signing_environment"] == {"GNUPGHOME": "/safe/gnupg"}
    publish_call = workspace.publish_calls[0]
    assert publish_call["credential_environment"]() == {"GIT_ASKPASS": "/safe/helper"}
    assert publish_call["signing_key"] == "ABCDEF"
    assert publish_call["signing_environment"] == {"GNUPGHOME": "/safe/gnupg"}
    assert [event["phase"] for event in state.events] == [
        "validated",
        "pushed",
        "draft_opened",
    ]
    assert order.index("state:validated") < order.index("remote:branch-push")
    assert order.index("state:pushed") < order.index("remote:draft-post")
    assert order.index("state:draft_opened") < order.index("checkpoint:12")
    assert [checkpoint["authority_scope"] for checkpoint in state.checkpoints] == [
        HistoricalCheckScope.REMEDIATION,
        HistoricalCheckScope.REMEDIATION,
    ]
    ledger = state.events[0]
    assert ledger["branch_identity_version"] == 2
    assert len(str(ledger["evidence_hash"])) == 64
    assert len(str(ledger["batch_hash"])) == 64
    assert str(ledger["branch"]).startswith("translation-updates-history-")
    assert "[Localize Guardian bot]" in str(ledger["title"])
    assert "human review only" in str(ledger["body"]).lower()
    assert all(url in str(ledger["body"]) for url in FEEDBACK_URLS)
    assert all(f"/pull/{number}" in str(ledger["body"]) for number in (12, 13))
    assert {call[0] for call in broker.calls} <= {
        "verify_publish_authority",
        "open_draft",
    }


def test_new_overlap_at_branch_push_boundary_blocks_all_remote_writes() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)
    initial_open_paths: frozenset[str] = frozenset()

    assert not initial_open_paths.intersection(_patch().changed_files)

    def newly_overlapping_authority(
        paths: object,
        excluded_pull: object,
    ) -> None:
        assert tuple(paths) == ("l10n/messages_ru.properties",)
        assert excluded_pull is None
        raise RemediationOpenPullAuthorityError("new overlapping open pull")

    with pytest.raises(RemediationOpenPullAuthorityError, match="overlapping"):
        _publish(
            _coordinator(state, broker),
            workspace,
            base,
            require_no_open_translation_overlap=newly_overlapping_authority,
        )

    assert "remote:branch-push" not in order
    assert "remote:draft-post" not in order
    assert [event["phase"] for event in state.events] == ["validated"]


def test_source_revalidation_runs_after_overlap_before_branch_push() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)
    source_current = True

    def overlap_then_reopen_source(_paths: object, _excluded: object) -> None:
        nonlocal source_current
        order.append("overlap")
        source_current = False

    def require_current_source(_sources: object, _revision_ids: object) -> None:
        order.append("exact-source")
        if not source_current:
            raise RemediationSourceAuthorityError("source changed during overlap scan")

    with pytest.raises(RemediationSourceAuthorityError, match="during overlap"):
        _publish(
            _coordinator(state, broker),
            workspace,
            base,
            require_exact_sources_still_closed=require_current_source,
            require_no_open_translation_overlap=overlap_then_reopen_source,
        )

    assert order.index("overlap") < max(
        index for index, value in enumerate(order) if value == "exact-source"
    )
    assert "remote:branch-push" not in order
    assert "remote:draft-post" not in order
    assert [event["phase"] for event in state.events] == ["validated"]


def test_fresh_nonoverlap_is_checked_at_push_and_both_pr_post_boundaries() -> None:
    order: list[str] = []
    base = _base_snapshot()
    checks: list[tuple[tuple[str, ...], object]] = []

    outcome = _publish(
        _coordinator(_StateSpy(order=order), _BrokerSpy(base, order=order)),
        _WorkspaceSpy(base, order=order),
        base,
        require_no_open_translation_overlap=lambda paths, excluded: checks.append(
            (tuple(paths), excluded)
        ),
    )

    assert len(outcome.drafts) == 1
    assert checks == [
        (("l10n/messages_ru.properties",), None),
        (("l10n/messages_ru.properties",), None),
        (("l10n/messages_ru.properties",), None),
    ]
    assert "remote:branch-push" in order
    assert "remote:draft-post" in order


def test_branch_only_recovery_rechecks_overlap_before_pr_post() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.branches[attempt.branch] = attempt.candidate_sha
    coordinator.begin_poll()
    order.clear()
    broker.calls.clear()
    recovered_workspace = _WorkspaceSpy(base, order=order)

    with pytest.raises(RemediationOpenPullAuthorityError, match="overlapping"):
        _publish(
            coordinator,
            recovered_workspace,
            base,
            require_no_open_translation_overlap=lambda _paths, _excluded: (
                _ for _ in ()
            ).throw(RemediationOpenPullAuthorityError("new overlapping open pull")),
        )

    assert recovered_workspace.commit_calls == []
    assert recovered_workspace.publish_calls == []
    assert "remote:branch-push" not in order
    assert "remote:draft-post" not in order


def test_branch_only_recovery_rechecks_source_after_overlap_before_pr_post() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.branches[attempt.branch] = attempt.candidate_sha
    coordinator.begin_poll()
    order.clear()
    broker.calls.clear()
    source_current = True

    def overlap_then_edit_feedback(_paths: object, _excluded: object) -> None:
        nonlocal source_current
        order.append("overlap")
        source_current = False

    def require_current_source(_sources: object, _revision_ids: object) -> None:
        order.append("exact-source")
        if not source_current:
            raise RemediationSourceAuthorityError(
                "feedback changed during overlap scan"
            )

    with pytest.raises(RemediationSourceAuthorityError, match="during overlap"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order),
            base,
            require_exact_sources_still_closed=require_current_source,
            require_no_open_translation_overlap=overlap_then_edit_feedback,
        )

    assert order.index("overlap") < max(
        index for index, value in enumerate(order) if value == "exact-source"
    )
    assert "remote:branch-push" not in order
    assert "remote:draft-post" not in order


@pytest.mark.parametrize(
    "paths",
    (
        tuple(f"l10n/messages_{index}.properties" for index in range(101)),
        ([],),
        ("../outside.properties",),
    ),
    ids=("too-many", "non-string", "unsafe"),
)
def test_remediation_changed_paths_enforce_runtime_bounds(paths: object) -> None:
    with pytest.raises(ValueError, match="bounded safe repository paths"):
        remediation_module._normalized_changed_paths(paths)  # type: ignore[arg-type]


def test_publish_lost_lease_after_push_stops_state_and_draft_post() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)

    def require_live_lease() -> None:
        order.append("lease")
        if "remote:branch-push" in order:
            raise RuntimeError("lease lost after push")

    with pytest.raises(RuntimeError, match="lease lost after push"):
        _publish(
            _coordinator(state, broker),
            workspace,
            base,
            require_live_lease=require_live_lease,
        )

    assert [event["phase"] for event in state.events] == ["validated"]
    assert [name for name, _values in broker.calls] == [
        "verify_publish_authority",
        "verify_publish_authority",
    ]
    assert state.remote_observations == []
    assert state.checkpoints == []


def test_publish_lost_lease_after_draft_post_stops_state_checkpoint() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)

    def require_live_lease() -> None:
        order.append("lease")
        if "remote:draft-post" in order:
            raise RuntimeError("lease lost after draft post")

    with pytest.raises(RuntimeError, match="lease lost after draft post"):
        _publish(
            _coordinator(state, broker),
            workspace,
            base,
            require_live_lease=require_live_lease,
        )

    assert [event["phase"] for event in state.events] == ["validated", "pushed"]
    assert state.remote_observations == []
    assert state.checkpoints == []


@pytest.mark.parametrize(
    ("failure_call", "expected_phases", "expected_remote_events"),
    (
        (1, ("validated",), ()),
        (2, ("validated", "pushed"), ("remote:branch-push",)),
        (3, ("validated", "pushed"), ("remote:branch-push",)),
        (
            4,
            ("validated", "pushed", "draft_opened"),
            ("remote:branch-push", "remote:draft-post"),
        ),
    ),
)
def test_current_base_guard_fails_closed_at_each_publication_boundary(
    failure_call: int,
    expected_phases: tuple[str, ...],
    expected_remote_events: tuple[str, ...],
) -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)
    checks = 0

    def require_current_base_unchanged() -> None:
        nonlocal checks
        checks += 1
        order.append("base")
        if checks == failure_call:
            raise RuntimeError("current base moved")

    with pytest.raises(RuntimeError, match="current base moved"):
        _coordinator(state, broker).publish(
            policy=_policy(),
            base=base,
            workspace=workspace,
            patch_result=_patch(),
            replacements=_replacements(),
            source_pulls=_source_pulls(),
            event_revision_ids=(101, 102),
            feedback_urls=FEEDBACK_URLS,
            run_id="run-1",
            observed_at=NOW,
            require_live_lease=lambda: order.append("lease"),
            require_current_base_unchanged=require_current_base_unchanged,
            require_exact_sources_still_closed=(
                lambda _sources, _revision_ids: order.append("sources")
            ),
            require_no_open_translation_overlap=lambda _paths, _excluded: None,
            prior_draft_keys_by_source={source: () for source in _source_pulls()},
            required_edit_hashes_by_source={
                source: tuple(
                    sorted(remediation_edit_hash(item) for item in _replacements())
                )
                for source in _source_pulls()
            },
        )

    assert tuple(event["phase"] for event in state.events) == expected_phases
    assert tuple(item for item in order if item.startswith("remote:")) == (
        expected_remote_events
    )
    assert state.checkpoints == []


def test_hashes_and_branch_are_stable_for_reordered_batch_inputs() -> None:
    ledgers: list[dict[str, object]] = []
    for replacements, source_pulls, urls in (
        (_replacements(), _source_pulls(), FEEDBACK_URLS),
        (
            tuple(reversed(_replacements())),
            tuple(reversed(_source_pulls())),
            tuple(reversed(FEEDBACK_URLS)),
        ),
    ):
        order: list[str] = []
        base = _base_snapshot()
        state = _StateSpy(order=order)
        broker = _BrokerSpy(base, order=order)
        coordinator = _coordinator(state, broker)
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order),
            base,
            replacements=replacements,
            source_pulls=source_pulls,
            feedback_urls=urls,
        )
        ledgers.append(state.events[0])

    assert {
        (
            ledger["evidence_hash"],
            ledger["batch_hash"],
            ledger["branch"],
            ledger["title"],
            ledger["body"],
        )
        for ledger in ledgers
    } == {
        (
            ledgers[0]["evidence_hash"],
            ledgers[0]["batch_hash"],
            ledgers[0]["branch"],
            ledgers[0]["title"],
            ledgers[0]["body"],
        )
    }


def test_fresh_v2_branch_identity_changes_for_a_policy_only_change() -> None:
    ledgers: list[dict[str, object]] = []
    for policy_digest in ("2" * 64, "9" * 64):
        order: list[str] = []
        base = _base_snapshot()
        state = _StateSpy(order=order)
        source_pulls = tuple(
            replace(source, policy_digest=policy_digest) for source in _source_pulls()
        )
        _publish(
            _coordinator(state, _BrokerSpy(base, order=order)),
            _WorkspaceSpy(base, order=order),
            base,
            source_pulls=source_pulls,
        )
        ledgers.append(state.events[0])

    assert ledgers[0]["evidence_hash"] == ledgers[1]["evidence_hash"]
    assert ledgers[0]["batch_hash"] == ledgers[1]["batch_hash"]
    assert ledgers[0]["branch"] != ledgers[1]["branch"]
    assert {ledger["branch_identity_version"] for ledger in ledgers} == {2}


def test_batch_and_branch_identity_ignore_model_and_feedback_metadata() -> None:
    from localize.guardian.remediation import _batch_hash, _branch_name

    original = _replacements()
    reassessed = tuple(
        replace(
            replacement,
            feedback_id=f"review_comment:replacement-{index}",
            confidence=0.51 + index / 100,
            evidence=(f"new free-form rationale {index}",),
        )
        for index, replacement in enumerate(original)
    )

    original_hash = _batch_hash(original)
    reassessed_hash = _batch_hash(tuple(reversed(reassessed)))
    assert reassessed_hash == original_hash
    assert _branch_name(
        prefix="translation-updates-history-",
        batch_hash=original_hash,
        target_base_sha=BASE_SHA,
        evidence_hash="e" * 64,
        branch_identity_version=2,
        policy_digests=("2" * 64,),
    ) == _branch_name(
        prefix="translation-updates-history-",
        batch_hash=reassessed_hash,
        target_base_sha=BASE_SHA,
        evidence_hash="e" * 64,
        branch_identity_version=2,
        policy_digests=("2" * 64,),
    )


def test_v2_branch_identity_changes_across_evidence_base_or_policy() -> None:
    from localize.guardian.remediation import _branch_name, _evidence_hash

    original = _record(phase="validated", base_sha=BASE_SHA)
    assert (
        original.branch
        != _record(
            phase="validated",
            base_sha="f" * 40,
        ).branch
    )
    assert original.branch != _branch_name(
        prefix="translation-updates-history-",
        batch_hash=original.batch_hash,
        target_base_sha=BASE_SHA,
        evidence_hash="f" * 64,
        branch_identity_version=2,
        policy_digests=("2" * 64,),
    )
    changed_policy = tuple(
        replace(source, policy_digest="9" * 64) for source in _source_pulls()
    )
    assert _evidence_hash(
        _source_pulls(), tuple(sorted(FEEDBACK_URLS))
    ) == _evidence_hash(changed_policy, tuple(sorted(FEEDBACK_URLS)))
    assert (
        original.branch
        != _record(
            phase="validated",
            policy_digest="9" * 64,
        ).branch
    )


def test_v1_branch_identity_ignores_policy_digest_for_migrated_records() -> None:
    from localize.guardian.remediation import _branch_name

    values = {
        "prefix": "translation-updates-history-",
        "batch_hash": "d" * 64,
        "target_base_sha": BASE_SHA,
        "evidence_hash": "e" * 64,
        "branch_identity_version": 1,
    }

    legacy_branch = _branch_name(**values, policy_digests=("2" * 64,))

    assert legacy_branch == (
        "translation-updates-history-"
        "415f65752e01216a6738ef3600a91014ffb8c887c7640e23a1554a9c112843d6"
    )
    assert legacy_branch == _branch_name(
        **values,
        policy_digests=("9" * 64,),
    )


def test_draft_body_does_not_interpolate_untrusted_paths_or_keys() -> None:
    hostile_path = "l10n/@maintainer.properties"
    hostile_key = "`</code><img src=x>@maintainer"
    replacement = replace(
        _replacements()[0],
        path=hostile_path,
        key=hostile_key,
    )
    patch = PatchResult(
        changed_files=(hostile_path,),
        changed_keys=((hostile_path, hostile_key),),
    )
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    workspace = _WorkspaceSpy(base, order=order)

    _coordinator(state, broker).publish(
        policy=_policy(),
        base=base,
        workspace=workspace,
        patch_result=patch,
        replacements=(replacement,),
        source_pulls=_source_pulls(),
        event_revision_ids=(101, 102),
        feedback_urls=FEEDBACK_URLS,
        run_id="run-1",
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
        require_exact_sources_still_closed=(
            lambda _sources, _revision_ids: order.append("sources")
        ),
        require_no_open_translation_overlap=lambda _paths, _excluded: None,
        prior_draft_keys_by_source={source: () for source in _source_pulls()},
        required_edit_hashes_by_source={
            source: (remediation_edit_hash(replacement),) for source in _source_pulls()
        },
    )

    body = str(state.events[0]["body"])
    assert hostile_path not in body
    assert hostile_key not in body
    assert "Changed localization files: 1" in body
    assert "Changed translation entries: 1" in body


def test_global_publication_cap_resets_per_poll_and_is_never_refunded() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    failing = _WorkspaceSpy(base, order=order, fail_after_push_slot=True)

    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(coordinator, failing, base)

    deferred_workspace = _WorkspaceSpy(base, order=order)
    assert _publish(coordinator, deferred_workspace, base).deferred == 1
    assert deferred_workspace.commit_calls == []

    coordinator.begin_poll()
    assert (
        len(_publish(coordinator, _WorkspaceSpy(base, order=order), base).drafts) == 1
    )


def test_publication_cap_does_not_block_exact_existing_pr_reconciliation() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.existing[attempt.branch] = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=attempt.candidate_sha,
        created=False,
    )
    workspace = _WorkspaceSpy(base, order=order)

    recovered = _publish(coordinator, workspace, base)

    assert recovered.drafts[0].created is False
    assert workspace.commit_calls == []
    assert workspace.publish_calls == []


def test_publish_immediately_retires_a_recovered_merged_draft() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.existing[attempt.branch] = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=attempt.candidate_sha,
        created=False,
        state="closed",
        merged=True,
        draft=False,
    )

    recovered = _publish(coordinator, _WorkspaceSpy(base, order=order), base)

    assert recovered.drafts[0].merged is True
    assert state.resolutions == {attempt.draft_key: "merged"}


def test_publication_cap_allows_only_one_new_draft_per_repository() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker, max_drafts=2)

    assert (
        len(_publish(coordinator, _WorkspaceSpy(base, order=order), base).drafts) == 1
    )
    deferred_workspace = _WorkspaceSpy(base, order=order)
    assert _publish(coordinator, deferred_workspace, base).deferred == 1
    assert deferred_workspace.commit_calls == []

    coordinator.begin_poll()
    assert (
        len(_publish(coordinator, _WorkspaceSpy(base, order=order), base).drafts) == 1
    )


def test_incompatible_pending_authority_blocks_a_semantic_duplicate() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    incompatible = replace(
        attempt,
        push_repository="former-owner/translations",
        push_repository_id=999,
    )
    state.pending = (incompatible,)
    coordinator.begin_poll()
    broker.calls.clear()
    workspace = _WorkspaceSpy(base, order=order)

    outcome = _publish(coordinator, workspace, base)

    assert outcome.deferred == 1
    assert outcome.retry_source_batches == ()
    assert workspace.commit_calls == []
    assert broker.calls == []


def test_active_same_target_with_different_value_defers_without_remote_calls() -> None:
    order: list[str] = []
    base = _base_snapshot()
    active = _record(phase="draft_opened")
    state = _StateSpy(opened=(active,), order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    changed = replace(_replacements()[0], proposed_value="different reviewed value")
    proposals = (changed, _replacements()[1])
    workspace = _WorkspaceSpy(base, order=order)

    outcome = _publish(
        coordinator,
        workspace,
        base,
        replacements=proposals,
    )

    assert outcome.deferred == 1
    assert outcome.drafts == ()
    assert workspace.commit_calls == []
    assert workspace.publish_calls == []
    assert broker.calls == []
    assert state.events == []


def test_fresh_publish_reuses_a_crash_recovered_branch_candidate() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.branches[attempt.branch] = attempt.candidate_sha
    coordinator.begin_poll()

    recovered = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )
    fresh_workspace = _WorkspaceSpy(base, order=order)
    published = _publish(coordinator, fresh_workspace, base)
    broker.existing[attempt.branch] = replace(
        published.drafts[0],
        created=False,
    )
    coordinator.begin_poll()
    second_workspace = _WorkspaceSpy(base, order=order)
    repeated = _publish(coordinator, second_workspace, base)

    assert recovered.deferred == 1
    assert recovered.retry_source_batches == (_source_pulls(),)
    assert len(published.drafts) == 1
    assert published.drafts[0].candidate_sha == attempt.candidate_sha
    assert fresh_workspace.commit_calls == []
    assert fresh_workspace.publish_calls == []
    assert repeated.drafts[0].created is False
    assert second_workspace.commit_calls == []
    assert [name for name, _ in broker.calls].count("open_draft") == 1


def test_fresh_publish_reconciles_lost_post_using_prior_evidence_identity() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.existing[attempt.branch] = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=attempt.candidate_sha,
        created=False,
    )
    later_sources = tuple(
        replace(
            source,
            pull_id=source.pull_id + 100,
            pr_number=source.pr_number + 100,
            pull_revision_digest="9" * 64,
        )
        for source in _source_pulls()
    )
    later_urls = (
        "https://github.test/acme/translations/pull/112#discussion_r100",
        "https://github.test/acme/translations/issues/113#issuecomment-200",
    )
    coordinator.begin_poll()
    workspace = _WorkspaceSpy(base, order=order)

    outcome = _publish(
        coordinator,
        workspace,
        base,
        source_pulls=later_sources,
        feedback_urls=later_urls,
    )

    assert outcome.drafts[0].created is False
    assert workspace.commit_calls == []
    assert workspace.publish_calls == []
    find_call = next(values for name, values in broker.calls if name == "find_draft")
    assert find_call["evidence_hash"] == attempt.evidence_hash
    assert find_call["title"] == attempt.title
    assert find_call["body"] == attempt.body
    assert {item["pr_number"] for item in state.checkpoints[-2:]} == {112, 113}


def test_fresh_publish_uses_new_branch_for_changed_evidence() -> None:
    order: list[str] = []
    base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(base, order=order, fail_after_push_slot=True),
            base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    broker.branches[attempt.branch] = attempt.candidate_sha
    later_sources = tuple(
        replace(
            source,
            pull_id=source.pull_id + 100,
            pr_number=source.pr_number + 100,
            pull_revision_digest="9" * 64,
        )
        for source in _source_pulls()
    )
    later_urls = (
        "https://github.test/acme/translations/pull/112#discussion_r100",
        "https://github.test/acme/translations/issues/113#issuecomment-200",
    )
    coordinator.begin_poll()
    workspace = _WorkspaceSpy(base, order=order)

    outcome = _publish(
        coordinator,
        workspace,
        base,
        source_pulls=later_sources,
        feedback_urls=later_urls,
    )

    assert outcome.drafts[0].created is True
    assert len(workspace.commit_calls) == 1
    assert len(workspace.publish_calls) == 1
    assert [event["phase"] for event in state.events] == [
        "validated",
        "abandoned",
        "validated",
        "pushed",
        "draft_opened",
    ]
    open_call = next(values for name, values in broker.calls if name == "open_draft")
    assert open_call["branch"] != attempt.branch
    assert open_call["evidence_hash"] != attempt.evidence_hash
    assert broker.branches[attempt.branch] == attempt.candidate_sha


def test_fresh_publish_does_not_reuse_a_branch_from_an_old_policy() -> None:
    order: list[str] = []
    base = _base_snapshot()
    prior = _record(phase="pushed", policy_digest="9" * 64)
    state = _StateSpy(pending=(prior,), order=order)
    broker = _BrokerSpy(
        base,
        order=order,
        branches={prior.branch: prior.candidate_sha},
    )
    workspace = _WorkspaceSpy(base, order=order)

    outcome = _publish(_coordinator(state, broker), workspace, base)

    assert outcome.drafts[0].created is True
    assert [event["phase"] for event in state.events] == [
        "abandoned",
        "validated",
        "pushed",
        "draft_opened",
    ]
    open_call = next(values for name, values in broker.calls if name == "open_draft")
    assert open_call["branch"] != prior.branch
    assert state.events[1]["branch_identity_version"] == 2
    assert {source.policy_digest for source in state.events[1]["source_pulls"]} == {
        "2" * 64
    }


def test_fresh_publish_replaces_a_validated_attempt_when_branch_is_absent() -> None:
    order: list[str] = []
    old_base = _base_snapshot()
    state = _StateSpy(order=order)
    broker = _BrokerSpy(old_base, order=order)
    coordinator = _coordinator(state, broker)
    with pytest.raises(RuntimeError, match="lost push response"):
        _publish(
            coordinator,
            _WorkspaceSpy(old_base, order=order, fail_after_push_slot=True),
            old_base,
        )
    attempt = RemediationDraftRecord(
        draft_key="e" * 64,
        draft_number=None,
        draft_pull_id=None,
        draft_url=None,
        **state.events[0],
    )
    state.pending = (attempt,)
    coordinator.begin_poll()
    new_base = _base_snapshot(sha="f" * 40)
    fresh_workspace = _WorkspaceSpy(new_base, order=order)

    published = _publish(coordinator, fresh_workspace, new_base)

    assert len(published.drafts) == 1
    assert len(fresh_workspace.commit_calls) == 1
    assert len(fresh_workspace.publish_calls) == 1
    assert [event["phase"] for event in state.events] == [
        "validated",
        "abandoned",
        "validated",
        "pushed",
        "draft_opened",
    ]


def test_recover_reconciles_a_migrated_v1_branch_identity() -> None:
    order: list[str] = []
    pending = _record(phase="pushed", branch_identity_version=1)
    recovered = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=pending.candidate_sha,
        created=False,
    )
    state = _StateSpy(pending=(pending,), order=order)
    broker = _BrokerSpy(
        _base_snapshot(),
        order=order,
        existing={pending.branch: recovered},
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.drafts == (recovered,)
    find_call = next(values for name, values in broker.calls if name == "find_draft")
    assert find_call["branch"] == pending.branch
    assert state.events[0]["branch_identity_version"] == 1


def test_recover_advances_exact_branch_and_requeues_uncheckpointed_sources() -> None:
    order: list[str] = []
    pending = _record(phase="validated")
    opened = _record(
        phase="draft_opened",
        batch_hash="6" * 64,
    )
    base = _base_snapshot()
    state = _StateSpy(pending=(pending,), opened=(opened,), order=order)
    existing = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=pending.candidate_sha,
        created=False,
    )
    opened_existing = replace(
        existing,
        candidate_sha=opened.candidate_sha,
    )
    broker = _BrokerSpy(
        base,
        order=order,
        branches={pending.branch: pending.candidate_sha},
        existing={pending.branch: existing, opened.branch: opened_existing},
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.drafts == (existing,)
    assert [event["phase"] for event in state.events] == ["pushed", "draft_opened"]
    assert outcome.checkpoints == 0
    assert state.checkpoints == []
    assert outcome.retry_source_batches == (_source_pulls(),)
    assert "remote:draft-post" not in order


def test_recover_legacy_draft_without_exact_paths_fails_closed() -> None:
    legacy = replace(_record(phase="pushed"), changed_paths=None)
    state = _StateSpy(pending=(legacy,))
    broker = _BrokerSpy(_base_snapshot(), order=[])

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
    )

    assert outcome.deferred == 1
    assert outcome.retry_source_batches == ()
    assert broker.calls == []


def test_legacy_opened_draft_never_infers_numeric_pull_identity() -> None:
    legacy = replace(_record(phase="draft_opened"), draft_pull_id=None)

    with pytest.raises(
        RemediationOpenPullAuthorityError,
        match="identity is unavailable",
    ):
        remediation_module._opened_pull_identity(legacy)


@pytest.mark.parametrize("remote_found", [False, True])
def test_recover_lost_lease_after_lookup_stops_all_later_state_mutations(
    remote_found: bool,
) -> None:
    order: list[str] = []
    pending = _record(phase="pushed")
    state = _StateSpy(pending=(pending,), order=order)
    broker = _BrokerSpy(
        _base_snapshot(),
        order=order,
        existing=(
            {
                pending.branch: RemediationDraftResult(
                    number=91,
                    html_url="https://github.test/acme/translations/pull/91",
                    candidate_sha=pending.candidate_sha,
                    created=False,
                )
            }
            if remote_found
            else {}
        ),
    )

    def require_live_lease() -> None:
        order.append("lease")
        if any(name == "find_draft" for name, _values in broker.calls):
            raise RuntimeError("lease lost after lookup")

    with pytest.raises(RuntimeError, match="lease lost after lookup"):
        _coordinator(state, broker).recover(
            policy=_policy(),
            policy_digest="2" * 64,
            observed_at=NOW,
            require_live_lease=require_live_lease,
            require_current_base_unchanged=lambda: order.append("base"),
        )

    assert state.events == []
    assert state.remote_observations == []
    assert state.checkpoints == []
    assert [name for name, _values in broker.calls] == ["find_draft"]


def test_recover_retires_merged_draft_from_active_target_coverage() -> None:
    opened = _record(phase="draft_opened")
    state = _StateSpy(opened=(opened,))
    merged = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=opened.candidate_sha,
        created=False,
        state="closed",
        merged=True,
        draft=False,
    )
    coordinator = _coordinator(
        state,
        _BrokerSpy(
            _base_snapshot(),
            order=[],
            existing={opened.branch: merged},
        ),
    )

    outcome = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
    )

    assert outcome.checkpoints == 0
    assert outcome.retry_source_batches == ()
    assert outcome.deferred == 1
    assert state.resolutions == {opened.draft_key: "merged"}
    replacement = replace(
        _replacements()[0],
        expected_value="new one",
        proposed_value="newer one",
    )
    coverage = state.remediation_edit_coverage(
        target_repository="acme/translations",
        target_repository_id=42,
        edit_target_hashes=(
            (remediation_edit_hash(replacement), remediation_target_hash(replacement)),
        ),
    )
    assert not coverage.conflicting_edit_hashes


def test_recover_records_remote_lifecycle_but_not_completion_after_base_moves() -> None:
    opened = _record(phase="draft_opened")
    state = _StateSpy(opened=(opened,))
    merged = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=opened.candidate_sha,
        created=False,
        state="closed",
        merged=True,
        draft=False,
    )

    with pytest.raises(RuntimeError, match="current base moved"):
        _coordinator(
            state,
            _BrokerSpy(
                _base_snapshot(),
                order=[],
                existing={opened.branch: merged},
            ),
        ).recover(
            policy=_policy(),
            policy_digest="2" * 64,
            observed_at=NOW,
            require_live_lease=lambda: None,
            require_current_base_unchanged=lambda: (_ for _ in ()).throw(
                RuntimeError("current base moved")
            ),
        )

    assert state.checkpoints == []
    assert state.resolutions == {opened.draft_key: "merged"}
    assert state.remote_observations[-1]["observation"] == "exact"


def test_recover_immediately_retires_a_pending_draft_found_merged() -> None:
    pending = _record(phase="validated")
    state = _StateSpy(pending=(pending,))
    merged = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=pending.candidate_sha,
        created=False,
        state="closed",
        merged=True,
        draft=False,
    )
    coordinator = _coordinator(
        state,
        _BrokerSpy(
            _base_snapshot(),
            order=[],
            existing={pending.branch: merged},
        ),
    )

    outcome = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
    )

    assert outcome.drafts == (merged,)
    assert state.resolutions == {pending.draft_key: "merged"}


def test_recover_abandons_branch_only_stale_policy_without_posting() -> None:
    order: list[str] = []
    stale = _record(phase="validated", policy_digest="9" * 64)
    opened = _record(
        phase="draft_opened",
        batch_hash="6" * 64,
    )
    base = _base_snapshot()
    state = _StateSpy(pending=(stale,), opened=(opened,), order=order)
    broker = _BrokerSpy(
        base,
        order=order,
        existing={
            opened.branch: RemediationDraftResult(
                number=92,
                html_url="https://github.test/acme/translations/pull/92",
                candidate_sha=opened.candidate_sha,
                created=False,
            )
        },
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.abandoned == 1
    assert outcome.deferred == 1
    assert outcome.retry_source_batches == (opened.source_pulls,)
    assert state.checkpoints == []
    assert [name for name, _ in broker.calls] == ["find_draft", "find_draft"]
    assert "remote:draft-post" not in order


def test_recover_reconciles_lost_post_response_after_policy_change() -> None:
    order: list[str] = []
    stale = _record(phase="pushed", policy_digest="9" * 64)
    recovered = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=stale.candidate_sha,
        created=False,
    )
    state = _StateSpy(pending=(stale,), order=order)
    broker = _BrokerSpy(
        _base_snapshot(),
        order=order,
        existing={stale.branch: recovered},
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.drafts == (recovered,)
    assert outcome.abandoned == 0
    assert [event["phase"] for event in state.events] == ["draft_opened"]
    assert "remote:draft-post" not in order


def test_recover_finds_existing_closed_draft_after_branch_was_deleted() -> None:
    order: list[str] = []
    pending = _record(phase="pushed")
    base = _base_snapshot(sha="f" * 40)
    state = _StateSpy(
        pending=(pending,),
        order=order,
        current_evidence_valid=False,
    )
    closed = RemediationDraftResult(
        number=91,
        html_url="https://github.test/acme/translations/pull/91",
        candidate_sha=pending.candidate_sha,
        created=False,
    )
    broker = _BrokerSpy(
        base,
        order=order,
        branches={pending.branch: None},
        existing={pending.branch: closed},
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.drafts == (closed,)
    assert outcome.abandoned == 0
    assert [event["phase"] for event in state.events] == ["draft_opened"]
    assert state.checkpoints == []
    assert outcome.retry_source_batches == (pending.source_pulls,)
    assert "remote:draft-post" not in order


def test_recover_abandons_branch_only_superseded_evidence() -> None:
    order: list[str] = []
    pending = _record(phase="pushed")
    state = _StateSpy(
        pending=(pending,),
        order=order,
        current_evidence_valid=False,
    )
    broker = _BrokerSpy(_base_snapshot(), order=order)

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.abandoned == 1
    assert outcome.deferred == 0
    assert outcome.retry_source_batches == ()
    assert [event["phase"] for event in state.events] == ["abandoned"]
    assert "remote:draft-post" not in order


def test_recover_abandons_all_attempts_with_superseded_exact_sources() -> None:
    first = _record(phase="pushed", batch_hash="6" * 64)
    second = _record(phase="pushed", batch_hash="7" * 64)
    state = _StateSpy(
        pending=(first, second),
        current_evidence_valid=False,
    )

    outcome = _coordinator(
        state,
        _BrokerSpy(_base_snapshot(), order=[]),
    ).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
    )

    assert outcome.abandoned == 2
    assert outcome.deferred == 0
    assert outcome.retry_source_batches == ()
    assert [event["phase"] for event in state.events] == [
        "abandoned",
        "abandoned",
    ]


def test_recovery_independently_bounds_pending_and_opened_remote_lookups() -> None:
    order: list[str] = []
    pending = tuple(
        _record(phase="pushed", batch_hash=f"{index:064x}") for index in range(101)
    )
    opened = tuple(
        _record(phase="draft_opened", batch_hash=f"{index + 200:064x}")
        for index in range(101)
    )
    state = _StateSpy(pending=pending, opened=opened, order=order)
    broker = _BrokerSpy(_base_snapshot(), order=order)

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert [name for name, _ in broker.calls].count("find_draft") == 200
    assert len(state.checkpoints) == 0
    assert outcome.deferred == 200


def test_pending_recovery_rotates_to_a_later_existing_pull() -> None:
    order: list[str] = []
    pending = tuple(
        _record(phase="pushed", batch_hash=f"{index:064x}") for index in range(101)
    )
    recovered = RemediationDraftResult(
        number=191,
        html_url="https://github.test/acme/translations/pull/191",
        candidate_sha=pending[-1].candidate_sha,
        created=False,
    )
    state = _StateSpy(pending=pending, order=order)
    broker = _BrokerSpy(
        _base_snapshot(),
        order=order,
        existing={pending[-1].branch: recovered},
    )
    coordinator = _coordinator(state, broker)

    first = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )
    second = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert first.drafts == ()
    assert second.drafts == (recovered,)


def test_policy_incompatible_pending_rows_cannot_starve_current_recovery() -> None:
    order: list[str] = []
    stale = tuple(
        replace(
            _record(phase="pushed", batch_hash=f"{index:064x}"),
            push_repository="former/translations",
        )
        for index in range(100)
    )
    current = _record(phase="pushed", batch_hash="f" * 64)
    recovered = RemediationDraftResult(
        number=191,
        html_url="https://github.test/acme/translations/pull/191",
        candidate_sha=current.candidate_sha,
        created=False,
    )
    state = _StateSpy(pending=(*stale, current), order=order)
    coordinator = _coordinator(
        state,
        _BrokerSpy(
            _base_snapshot(),
            order=order,
            existing={current.branch: recovered},
        ),
    )

    first = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )
    second = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert first.drafts == ()
    assert first.deferred == 100
    assert second.drafts == (recovered,)


def test_recovery_does_not_return_group_larger_than_current_poll_cap() -> None:
    pending = _record(phase="pushed")
    state = _StateSpy(pending=(pending,))
    policy = _policy()
    assert policy.closed_pr_backfill is not None
    policy = replace(
        policy,
        closed_pr_backfill=replace(
            policy.closed_pr_backfill,
            max_prs_per_poll=1,
        ),
    )

    outcome = _coordinator(state, _BrokerSpy(_base_snapshot(), order=[])).recover(
        policy=policy,
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
    )

    assert outcome.deferred == 1
    assert outcome.retry_source_batches == ()
    assert state.recovery_attempts[pending.draft_key] > 0


def test_stale_opened_records_do_not_starve_a_current_source_retry() -> None:
    order: list[str] = []
    stale = tuple(
        _record(
            phase="draft_opened",
            batch_hash=f"{index:064x}",
            policy_digest="9" * 64,
        )
        for index in range(101)
    )
    current = _record(phase="draft_opened", batch_hash="f" * 64)
    state = _StateSpy(opened=(*stale, current), order=order)
    coordinator = _coordinator(
        state,
        _BrokerSpy(
            _base_snapshot(),
            order=order,
            existing={
                current.branch: RemediationDraftResult(
                    number=191,
                    html_url="https://github.test/acme/translations/pull/191",
                    candidate_sha=current.candidate_sha,
                    created=False,
                )
            },
        ),
    )

    first = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )
    second = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert first.checkpoints == 0
    assert second.checkpoints == 0
    assert second.retry_source_batches == (current.source_pulls,)
    assert current.draft_key not in state.checkpointed_drafts


def test_recover_defers_branch_only_records_without_checkpointing() -> None:
    order: list[str] = []
    missing = _record(
        phase="pushed",
        batch_hash="7" * 64,
    )
    drifted = _record(
        phase="pushed",
        candidate_sha="7" * 40,
        batch_hash="9" * 64,
    )
    recovered = _record(
        phase="pushed",
        candidate_sha="a" * 40,
        batch_hash="c" * 64,
    )
    current = _base_snapshot(sha="f" * 40)
    state = _StateSpy(pending=(missing, drifted, recovered), order=order)
    closed = RemediationDraftResult(
        number=92,
        html_url="https://github.test/acme/translations/pull/92",
        candidate_sha=recovered.candidate_sha,
        created=False,
    )
    broker = _BrokerSpy(
        current,
        order=order,
        branches={
            missing.branch: None,
            drifted.branch: drifted.candidate_sha,
            recovered.branch: recovered.candidate_sha,
        },
        existing={recovered.branch: closed},
    )

    outcome = _coordinator(state, broker).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
    )

    assert outcome.drafts == (closed,)
    assert outcome.abandoned == 0
    assert outcome.deferred == 3
    assert [event["phase"] for event in state.events] == ["draft_opened"]
    assert state.checkpoints == []
    assert outcome.retry_source_batches == (recovered.source_pulls,)
    assert "remote:draft-post" not in order


def _merged_revalidation_items() -> tuple[MergedRemediationRevalidation, ...]:
    return tuple(
        MergedRemediationRevalidation(
            revalidation_key=str(index + 1) * 64,
            draft_key="f" * 64,
            source=source,
            event_revision_ids=(101 + index,),
            phase="pending",
            occurred_at=NOW,
        )
        for index, source in enumerate(_source_pulls())
    )


def test_recover_rotates_durable_merged_sources_before_returning_retry() -> None:
    order: list[str] = []
    state = _StateSpy(order=order)
    state.merged_revalidations.extend(_merged_revalidation_items())

    outcome = _coordinator(
        state,
        _BrokerSpy(_base_snapshot(), order=order),
    ).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: order.append("lease"),
        require_current_base_unchanged=lambda: order.append("base"),
        require_exact_sources_still_closed=(
            lambda _sources, _revision_ids: order.append("sources")
        ),
    )

    assert state.merge_revalidation_attempts == ["1" * 64, "2" * 64]
    assert state.merge_revalidation_outcomes == {}
    assert outcome.retry_source_batches == (_source_pulls(),)
    assert outcome.deferred == 2
    assert [item for item in order if item != "lease"] == [
        "base",
        "sources",
        "sources",
    ]


def test_recover_quarantine_veto_terminals_merged_queue_without_retry() -> None:
    state = _StateSpy()
    state.merged_revalidations.extend(_merged_revalidation_items())

    def veto(_sources: object, _revision_ids: object) -> None:
        raise RemediationSourceAuthorityError("operator quarantined")

    outcome = _coordinator(
        state,
        _BrokerSpy(_base_snapshot(), order=[]),
    ).recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
        require_exact_sources_still_closed=veto,
    )

    assert outcome.retry_source_batches == ()
    assert state.merge_revalidation_outcomes == {
        "1" * 64: "no_longer_applicable",
        "2" * 64: "no_longer_applicable",
    }


def test_recover_isolates_merged_source_authority_loss_from_exact_source() -> None:
    state = _StateSpy()
    first, second = _merged_revalidation_items()
    state.merged_revalidations.extend((first, second))
    authority_checks: list[
        tuple[tuple[HistoricalPullReference, ...], tuple[int, ...]]
    ] = []

    def validate_source(
        sources: object,
        revision_ids: object,
    ) -> None:
        exact_sources = tuple(sources)  # type: ignore[arg-type]
        exact_revision_ids = tuple(revision_ids)  # type: ignore[arg-type]
        authority_checks.append((exact_sources, exact_revision_ids))
        if exact_sources == (first.source,):
            raise RemediationSourceAuthorityError("source was reopened")

    coordinator = _coordinator(
        state,
        _BrokerSpy(_base_snapshot(), order=[]),
    )
    first_pass = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
        require_exact_sources_still_closed=validate_source,
    )

    assert state.merge_revalidation_outcomes == {
        first.revalidation_key: "no_longer_applicable"
    }
    assert first_pass.retry_source_batches == ((second.source,),)
    assert first_pass.deferred == 2
    assert authority_checks == [
        ((first.source,), first.event_revision_ids),
        ((second.source,), second.event_revision_ids),
    ]

    state.completed_sources.add(state._completion_identity(second.source))
    second_pass = coordinator.recover(
        policy=_policy(),
        policy_digest="2" * 64,
        observed_at=NOW,
        require_live_lease=lambda: None,
        require_current_base_unchanged=lambda: None,
        require_exact_sources_still_closed=validate_source,
    )

    assert state.merge_revalidation_outcomes == {
        first.revalidation_key: "no_longer_applicable",
        second.revalidation_key: "resolved",
    }
    assert second_pass.retry_source_batches == ()
    assert second_pass.deferred == 0
