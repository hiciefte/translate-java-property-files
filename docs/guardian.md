# Localize Guardian

Localize Guardian is an optional, self-hosted review loop for translation pull
requests. It revisits open PRs and, when explicitly configured, a bounded set of
closed PRs; records new authorized reviewer feedback revisions; asks Codex CLI
for a structured assessment; and applies only corrections that pass
deterministic localization policy.

This is not a hosted service. The operator runs the Guardian on infrastructure
they control, supplies their own Codex/ChatGPT plan or explicitly opts into API
billing, and bears any GitHub costs. The operator is responsible for its
allowlists, credentials, logs, updates, plan allowance or API charges, and
recovery. Operating it does not grant the translation pipeline maintainers
credentials or private access to the consuming project.

Start with `observe`. Treat every broader mode as a local write-authority change
that needs review on the operator-controlled Guardian host.

## Authority modes

The configured mode is a ceiling. A command-line option cannot raise the
authority granted by the operator-owned config.

| Mode | Maximum authority |
| --- | --- |
| `observe` | Report-only intake, assessment, audit records, and local status. It creates no commits, pushes, comments, or other GitHub writes. This is the default. |
| `prepare` | Everything in `observe`, plus validation of eligible value-only replacements in a disposable local checkout. It stores the outcome and a changed-key count in private action state, but retains no patch or reviewable plan. It cannot push or comment. |
| `apply-owned-translations` | Advance an allowed, Guardian-owned translation PR with validated value replacements, then post one concise status reply. An independently configured closed-PR remediation policy may also create bounded current-base correction PRs ready for review. |
| `propose-prevention` | Everything above, plus at most the configured number of prevention PRs per poll, shared across repositories, for recurring pipeline defects. It never merges either kind of PR. |

The CLI creates new prevention and historical-correction PRs **ready for review**
so repository review bots can start immediately. Signing, regression validation,
numeric actor/repository checks, and publication limits are unchanged. Recovery
accepts both ready-created PRs and older drafts with a one-way ready transition;
it never reopens or converts an existing PR. The internal `draft` ledger names
and `max_*_drafts_per_run` keys are retained for compatibility and still bound
all new publications. Low-level broker callers retain draft creation by default;
the runtime explicitly selects ready creation. This does not implement automatic
review follow-up on pipeline prevention PRs, nor enable automatic merging.

Review bots may append release notes to a PR description. Recovery still requires
every byte of the Guardian-authored body and its evidence marker to match the
private ledger. It additionally permits one appended CodeRabbit release-note
block of at most 8 KiB, bounded by its standard start/end markers. This suffix
is untrusted commentary, not proof of its author's identity or authority for
any edit. Rewritten original text, nested markers, arbitrary trailing text, and
oversized annotations remain conflicts; repository, actor, head, and lifecycle
checks still apply. The complete remediation body retains its existing size cap.

The Guardian does not merge pull requests, approve reviews, resolve review
threads, delete or edit reviewer comments, overwrite an existing remote ref, or
broaden its own policy. A human remains responsible for accepting translations
and prevention work.

## Trust model

The Guardian treats review comments, repository content, pull-request metadata,
and model output as untrusted data. Any of them can contain prompt injection or
malformed content. The controller never treats text from those sources as a
command, policy change, credential request, or authorization decision.

Authorization comes only from the local Guardian config, which should live
outside every monitored checkout. Across intake, assessment, validation, and
the final remote-write boundary, the controller enforces:

- exact base repository numeric ID;
- exact configured target base branch (`base_branch`);
- exact open PR, PR-author ID, head-repository ID, head-owner ID, and allowed
  branch pattern;
- unchanged head SHA and base SHA since assessment;
- allowed localization target path, locale, and key;
- the expected value and source value still match;
- placeholder multiplicity, glossary, encoding, mojibake, and adapter
  round-trip checks pass;
- per-run value-edit limits, and a model call starts only when a durable slot is
  available under the configured UTC daily model-call budget.

The localization pipeline config and glossary are inputs to validation, not
sources of Guardian authority. The backward-compatible default,
`pipeline_config_source: base`, loads them from the exact trusted base SHA,
never from the PR head. Their paths must remain inside that trusted tree.

For a project whose pipeline config must stay outside its repository, set
`pipeline_config_source: operator`. The existing relative
`pipeline_config_path` then resolves beside the private Guardian YAML. Before
any GitHub or model work, each scheduled or manual poll reads the pipeline
config and its configured (or default) safe relative glossary through
non-following file descriptors and snapshots them into a private per-poll
bundle. The Guardian YAML directory and every bundle directory must be owned by
the current operator with mode `0700`; pipeline-config and glossary files must
be current-user-owned, non-symlink regular files with mode `0600`. Inputs are
bounded and must be valid UTF-8 YAML or JSON. Unsafe ancestors, absolute paths,
parent traversal, malformed content, and an absent explicitly configured
glossary fail closed. A missing implicit default `glossary.json` remains valid,
matching pipeline behavior.

The private snapshot cannot change when an operator file is replaced during a
poll. Its deterministic digest enters model evidence and the assessment cache
identity. In both source modes, source-locale strings still come only from the
exact base SHA, and the configured profile source locale must match the
Guardian's local `source_locale` policy. A PR that changes these inputs cannot
use its changed versions to authorize itself.

On the translation-correction path, only value-only replacements are eligible.
The read-only assessment model cannot add or remove keys, edit a source-locale
file, choose a new path or locale, or replace whole files. A stale observation
fails closed and is reconsidered on a later run. The separate, opt-in prevention
author may change executable pipeline code only within its explicit code/test
allowlists and the additional controls described below.

### Reviewer authorization

Trust is set per repository and locale. Put native human reviewers under
`trusted_reviewers` and deterministic service accounts under `trusted_bots`.
Each entry includes its immutable numeric GitHub ID and expected API type. Login
names are display labels only; they never grant authority.

The same rule applies to repository ownership. `base_repo_id` and each
`allowed_head_repositories[].id` are authoritative. `base_repo` is also the
expected current API route and must be updated after a base-repository rename.
An allowed head repository's `full_name` is operator-readable routing metadata;
fresh PR authorization follows its numeric ID, so a rename is not confused with
an account that reuses the old name.

Human and bot lists are deliberately separate, but both can be explicit feedback
authorities. A bot whose numeric ID is listed under `trusted_bots` may authorize
auto-application for that repository and locale; this supports automated review
nitpicks. It never inherits trust from `trusted_reviewers`, and a human entry
never authorizes a bot with the same display name. Every resulting proposal
still passes the same model-output and deterministic value policy. IDs must be
unique across both lists for a locale. Each operator must replace every example
ID with values read from GitHub's API.

For each allowed open PR, intake paginates issue comments, review bodies, and
inline review comments. Each authorized edit or deletion is a new immutable
observation; it is not silently replaced in the audit trail. Feedback outside
the configured reviewer/bot and locale allowlists cannot authorize work and is
not sent to Codex. The Guardian's own marked status replies are excluded from
authorization and assessment.

### Private repositories

Repository visibility is read from GitHub before any model call. A private
repository requires explicit opt-in through `private_repo_model_opt_in: true`.
Without that opt-in, no private review text or repository evidence is sent to
Codex. Before enabling it, the operator must confirm that their OpenAI account,
data controls, and organizational policy permit the transfer.

## Codex assessment boundary

The Guardian uses the non-interactive `codex exec` interface described in the
[official Codex documentation](https://learn.chatgpt.com/docs/non-interactive-mode).
It runs the assessment with a sanitized evidence directory and a fixed JSON
Schema. A custom `guardian_evidence` permission profile grants minimal
filesystem reads plus read access to the evidence workspace. The driver uses
`--ephemeral`, `--output-schema`, `--json`, `--skip-git-repo-check`,
`--ignore-user-config`, `--ignore-rules`, `--strict-config`, and
`--ask-for-approval never`. Review text remains data rather than shell input or
a command-line argument.

Codex receives no GitHub write or signing credential. Its tool processes inherit
no model credential, and it cannot edit the monitored checkout. The controller
rejects missing, invented, duplicated, oversized, non-UTF-8, or schema-invalid
output. It then reconstructs locale, feedback identity, and source values from
trusted controller data and independently applies every policy check. Structured
output constrains parsing; it does not make model output trusted.

### Process containment

Every Codex invocation and focused prevention test runs in a new process
session with inherited CPU, file-size, descriptor, and supported process-count
limits. On Linux, the Guardian additionally requires a fresh cgroup-v2 leaf for
each bounded invocation. It joins the direct child before `exec`, activates the
kernel's recursive `cgroup.kill` control on every completion path, waits for
`populated 0`, and only then removes the leaf. The leaf's maximum depth and
descendant-cgroup count are both zero, so a child cannot leave empty nested
cgroups behind. This includes a descendant that calls `setsid()` or `setpgid()`
and escapes the original process group.

The operator's Linux service or container cgroup must be delegated so Guardian
can create those transient leaves. `guardian doctor` performs a
real create/join/kill/remove canary and fails closed when cgroup v2, delegation,
or `cgroup.kill` is unavailable. The cgroup is a lifecycle boundary, not a
filesystem sandbox: the Codex and prevention-test sandbox canaries also require
that an untrusted tool cannot open the parent `cgroup.procs` for writing. That
denial prevents a same-user descendant from migrating out of the leaf.

macOS has no cgroup-v2 equivalent. There the resource limits, process-group
cleanup, Codex permission profile, and operator-supplied prevention sandbox
remain in force, but process-group cleanup alone is not a hard boundary against
a deliberately detached descendant. Operators who require kernel-enforced
descendant teardown should run the Guardian in a Linux container or VM whose
outer runtime also tears down the complete container on exit.

The shipped Guardian default is `gpt-5.6-terra` with reasoning effort `high`.
Terra is OpenAI's balanced intelligence/cost model and currently uses about
half Sol's Codex token-credit rate; `high` retains deliberate reasoning for
semantic review while every proposed action remains deterministically checked.
See the
[official GPT-5.6 Terra model reference](https://developers.openai.com/api/docs/models/gpt-5.6-terra)
and [Codex rate card](https://help.openai.com/en/articles/11481834). Model and
effort remain explicit operator policy: use Sol/max only when representative
evaluations justify the additional plan allowance or API cost.

### Plugin isolation

`localize guardian` deliberately does not run the translation plugin loader.
An explicit `--plugin` argument is rejected, while
`LOCALIZE_PLUGIN_MODULES` and installed `localize.format_adapters` entry points
are ignored. This prevents project plugin code from running in the
credential-bearing Guardian process. Only the package's built-in registered
adapters are available; a trusted-base pipeline config that requires a custom
adapter fails closed during a run. `doctor` reports the adapters already
registered in that isolated process, but it does not claim custom-project
compatibility.

## Install and configure

Prerequisites:

- Python 3.11 or later and the `localize` package;
- Codex CLI plus either a ChatGPT-plan login (the default) or an explicitly
  selected API credential;
- Git and an explicit OpenPGP or agent-backed SSH signing identity for every
  Guardian write mode;
- a narrowly scoped GitHub credential available from an OS secret store;
- a persistent local directory for state and logs.

Create an operator-owned config from the report-only example:

```bash
GUARDIAN_CONFIG="$HOME/.config/localize/guardian.yaml"
install -d -m 700 "$HOME/.config/localize"
localize guardian init --config "$GUARDIAN_CONFIG"
```

`init` refuses to overwrite an existing file. Compare its output with
[`examples/guardian.config.yaml`](../examples/guardian.config.yaml), then set the
repository, owned PR/head identities, branch and path constraints, locales, and
numeric reviewer IDs. Keep `mode: observe` until `doctor`, a manual run, and the
local audit output are clean.

The Guardian config is strict: unknown fields, duplicate YAML keys, unsafe
relative paths, duplicate identities, and malformed limits are errors. Never
load it from a pull-request head or let a monitored repository modify it.
Use `pipeline_config_source: operator` only when the pipeline config and
glossary are stored under the same private config directory as described
above; `base` remains the default.

### Codex authentication and credentials

The default, `codex_auth_mode: chatgpt`, consumes the operator's Codex access
and ChatGPT plan allowance, not metered API billing. It can still consume
purchased ChatGPT/Codex credits when the operator's account or workspace allows
them, so it is not a guarantee of zero marginal cost. First create the config,
then perform one device login into the dedicated `codex_home`:

```bash
localize guardian login --config "$GUARDIAN_CONFIG"
```

`guardian login` forces `forced_login_method="chatgpt"` and
`cli_auth_credentials_store="file"`, and Codex refreshes the cached login when
needed. The Guardian requires the dedicated directory to be owned by the
current user with mode `0700`, and its non-symlink `auth.json` to be a regular
user-owned file with mode `0600`. Treat that file as a password: do not copy,
publish, back it up to a shared location, or commit it. The generated scheduler
points at the same private login, so no interactive login is required during a
scheduled poll. See the
[official Codex authentication guide](https://developers.openai.com/codex/auth)
for the distinction between ChatGPT and API-key authentication.

The login, status check, assessment, and prevention-author processes receive a
minimal environment. In particular, inherited `CODEX_API_KEY` and
`OPENAI_API_KEY` are removed, while the forced authentication method prevents
an accidental switch from plan allowance to API billing. Codex tool processes
receive neither the subscription credential directory nor a model API key.

API-key mode is an explicit opt-in. Set `codex_auth_mode: api-key`, remove
`codex_home`, configure `runtime.codex_api_key_command`, and configure both USD
limits. In API-key mode, the self-hosted Guardian does not accept an ambient API
key. Instead it invokes the configured operator-owned helper just in time, injects
`CODEX_API_KEY` only into the bounded Codex process, and uses an ephemeral Codex
home. The helper must print one API key to stdout and nothing else. Keep it
outside monitored repositories and backed by an OS secret store.

GitHub secrets are also never stored in Guardian YAML, launchd property lists,
generated wrappers, state, model evidence, or logs. Configure an OS-secret-store
token helper before installation. The helper must print one repository-scoped
token to stdout and nothing else; prefer a short-lived token when the provider
supports one. It is invoked as an argv array with `shell=False`, a timeout, and
redacted errors. The token is retained only in memory for the bounded Guardian
operation; temporary Git askpass material is removed afterward. Write scopes
are used only for an authorized translation branch update and status reply, an
explicitly configured prevention branch and PR, or an explicitly
configured current-base remediation branch and PR. Historical remediation
publication is available in `apply-owned-translations` or
`propose-prevention`; prevention publication is available only in
`propose-prevention`.

On macOS, either helper can retrieve its credential from Keychain. Keep helpers
outside monitored repositories, owned by the operator, and executable only by
that user. Do not put a token literal in a helper, environment file, or
scheduler argument.

### Commit signing

OpenPGP is the backward-compatible default. Keep `signing_format: openpgp`, set
`signing_program` to the trusted GPG executable, and set `signing_key` to the
full 40- or 64-hex fingerprint (optionally suffixed by `!` for an exact GPG key
selector). Existing OpenPGP installations need no migration.

Agent-backed Git SSH signing is an opt-in alternative:

```yaml
runtime:
  signing_format: ssh
  signing_program: /usr/bin/ssh-keygen
  signing_key: SHA256:REPLACE_WITH_EXACT_PUBLIC_KEY_FINGERPRINT
  signing_public_key: /absolute/path/to/guardian-signing-key.pub
```

`signing_key` is the exact unpadded SHA-256 fingerprint printed by
`ssh-keygen -l -E sha256 -f <public-key>`. The public-key file must contain
exactly one supported key. It must be an absolute, non-symlink regular file,
owned by the operator or root, not writable by group or other users, and have
one link. Its ancestors must also be trusted. DSA, malformed or multiple keys,
RSA keys below 3072 bits, and a fingerprint mismatch fail closed.

The Guardian never reads or stores an SSH private key. Before external poll
work it copies the validated public key into a private bounded snapshot and
derives a one-key `allowed-signers` file. Git selects that frozen public key and
asks the existing `ssh-agent` for the matching private operation. The validated
agent endpoint must have a private `0700` parent. If a higher macOS system
directory is root-owned but group-writable, Guardian hard-links the exact socket
inode into the private signing snapshot and verifies both names before use;
ordinary mutable ancestors still fail closed. `SSH_AUTH_SOCK` is passed only to
the `git commit` subprocess—not to Codex,
credential helpers, repository fetch/push, signature verification, or focused
tests. The resulting commit is verified against the one-key trust file both
after creation and immediately before publication.

An existing GitHub SSH signing key can therefore be reused when its private
half is already available through the operator's agent; only its public half
and exact fingerprint enter config. Register the public key as a GitHub signing
key as usual. On macOS, Keychain can remember the private key, but it must also
be available to the launchd-visible agent (for example via
`ssh-add --apple-use-keychain`). Do not place a private-key path, private key,
or a literal agent-socket path in Guardian YAML or a launchd property list.
Run `guardian doctor` from the same user/session used by the scheduled job; its
real sign-and-verify probe catches an unavailable agent or key before writes
are enabled.

Interactive runs may resolve tools from the operator's `PATH`. Before staging a
LaunchAgent, set `runtime.codex_executable`, `runtime.git_executable`,
`runtime.github_token_command[0]`, and—only in API-key mode—
`runtime.codex_api_key_command[0]` to actual executable absolute paths. A write
mode also requires an absolute `runtime.signing_program`. These paths must be
non-symlink, operator- or root-owned executables with trusted parent directories;
interpreted helpers must use an absolute interpreter in their shebang. In
particular, an npm shim or script using `#!/usr/bin/env node` is rejected: point
`codex_executable` at the package's platform-native Codex binary instead.
Every custom credential command must contain exactly one argv item naming the
inspected helper. The sole multi-item exception is the exact GitHub CLI command
`gh auth token`. Python, Node, shells, `nice`, `nohup`, and other interpreter or
dispatcher programs are not accepted as `argv[0]` with an unchecked helper
script in a later argument. A credential helper may itself be an executable
script, because Guardian inspects that script and its absolute shebang
interpreter chain; the shebang itself must contain only the interpreter path,
without flags or other arguments. `guardian doctor` resolves interactive
command names and validates each resulting executable before invoking any of
them. `guardian install` additionally requires absolute configured paths. Every
due scheduled run checks the executable and its interpreter chain again before
credentials or repository data are used, so a background process cannot
silently pick up a replaced binary from a changed `PATH`.

A model-credential-helper failure in API-key mode or any Codex authentication
failure opens the poll's authentication circuit, as does a GitHub
credential-helper or API authentication failure. The circuit stops later
repository and model work in that poll. Non-authentication GitHub transport,
API, and policy failures fail closed as ordinary repository or candidate
failures; later policy-scoped work may still be attempted.

An exhausted ChatGPT allowance, insufficient Codex credits, or a hard API
billing quota opens a separate model-capacity circuit. The Guardian does not
immediately retry that non-recoverable condition or start model work for later
repositories in the poll. It records only a redacted health outcome; inspect the
provider account for the reset time or billing decision.

### Preflight and first run

```bash
localize guardian login --config "$GUARDIAN_CONFIG"
localize guardian doctor --config "$GUARDIAN_CONFIG"
localize guardian run --config "$GUARDIAN_CONFIG"
localize guardian status --config "$GUARDIAN_CONFIG"
```

`doctor` makes no monitored-repository or GitHub writes and redacts credential
material. It checks the config, state directory and process-lock safety without
acquiring an active poll lock, the Codex executable and schema,
the dedicated ChatGPT login or API-key helper, GitHub credential helper,
GitHub identity, repository visibility, signing setup, and built-in adapters
registered in the isolated Guardian process. Target-project adapter
compatibility is checked later from the exact base checkout during a run.

In either write mode, every repository must name a top-level
`publication_actor`, and the same read-only probe resolves `/user` once. That
credential's immutable numeric ID and API type must match every repository's
actor. If a positive publication cap enables nested remediation or prevention
draft creation, each enabled nested actor must be the same identity;
configurations that would require different actors fail closed. Neither the
token nor mutable login is printed.

The publication actor must have GitHub API type `User`. Use a narrowly scoped
personal access token for a dedicated machine user, or another user token that
GitHub supports on
[`GET /user`](https://docs.github.com/en/rest/users/users#get-the-authenticated-user).
A GitHub App installation access token writes as a `Bot` but cannot satisfy
this user-identity proof, so installation-token publication is intentionally
rejected. Supporting it would require a separate installation-identity
protocol. This restriction applies only to publication; review feedback from
explicitly configured bots remains supported.

For `apply-owned-translations` and `propose-prevention`, set
`runtime.signing_key` explicitly (and `runtime.signing_public_key` for SSH).
The doctor creates an ephemeral local commit and proves that exact key can sign
and verify with global and system Git config disabled—the same isolation
boundary used for Guardian commits. For SSH it also uses the private one-key
allowed-signers snapshot and withholds the agent socket from verification. A
global `user.signingkey` is deliberately not accepted.
Each operator-run `guardian run` executes one finite poll.
`limits.run_timeout_seconds` is one elapsed-time budget measured against a
monotonic deadline for active work, not a fresh timeout for each repository,
request, page, retry, or subprocess. Setup snapshots and recursive workspace
scans check the same deadline; GitHub streaming and pagination recheck it between
chunks and pages; credential helpers, Codex, prevention tests, signing inspection,
and Git subprocesses receive no more than the remaining budget. Expiry stops new
work and prevents later remote mutations. Bounded SQLite finalization, recovery
bookkeeping, process teardown, temporary-file cleanup, and lease release may
finish after expiry so timeout handling cannot strand unsafe or misleading state.

`status` shows the last completed feedback run,
component health, pending feedback revisions and historical hydration retries,
aggregate action and remediation lifecycle counts, and current UTC daily model
calls (completed plus active or unknown reservations) without printing raw
review bodies or secrets. In API-key mode it additionally shows committed API
cost (settled cost plus active or unknown reservations).

Two bounded, redacted operator worklists expose durable recovery state under
the same exclusive poll lock:

```bash
localize guardian remediation list --config "$GUARDIAN_CONFIG" --limit 100
localize guardian history-retry list --config "$GUARDIAN_CONFIG" --limit 100
```

`remediation list` is the detailed provenance and lifecycle surface. It orders
active attempts before terminal local history and explicitly reports when the
requested attempt bound or the per-draft coverage bound truncates output. For
each bounded result it prints the draft key and branch-identity version; exact
target, push, ref, and commit identities; local publication phase; PR number
and canonical URL when present; terminal resolution; the latest remote
observation and its state/draft/merged/base/time fields; and the exact source
PR, policy, revision, coverage reason, linked draft keys, and whether that
coverage is currently effective. It never prints review-comment bodies.
`status` intentionally keeps this information aggregated.

`remediation quarantine` requires
`--acknowledge-terminal-local-skip` and atomically appends an
`operator_quarantined` resolution plus terminal coverage for every exact source
linked to the listed local attempt. It is an explicit terminal local skip, not
an inference from remote absence, and does not change its remote branch or pull
request.
`history-retry quarantine` requires the exact repository name and numeric ID,
policy digest, pull ID, PR number, and the same acknowledgement. It is a
deliberately permanent source-PR veto under that policy digest: later comments
on that PR are ignored while the policy is unchanged, and changing the policy
makes the PR eligible again. Neither command edits, closes, reopens, comments
on, or otherwise changes GitHub state.

Review at least one real report-only run before moving to `prepare`. The
`status` command shows aggregate action state, not the prepared key count or a
diff. Because the validated checkout is disposable and no patch is retained,
use a controlled test PR and the configured deterministic limits before
enabling `apply-owned-translations`; do not treat `prepare` as a reviewable diff
preview.

## What can be written

In `apply-owned-translations`, the Guardian writes only to a PR that still
matches every configured ownership constraint. It creates a signed, normal
descendant commit and advances the existing head without force. It never creates
an unrelated project runner or commits project-specific policy to this pipeline
repository.

Every repository in either write mode must configure a top-level
`publication_actor`. It is the exact GitHub actor that publishes ordinary
translation commits and authors status comments, identified authoritatively by
numeric ID and API type `User`; its login is display-only audit metadata. This actor
is deliberately independent of `allowed_pr_authors`, which controls which
existing PR owners may have their branches advanced, so the publication actor
does not gain PR-ownership authority by being configured. The write broker
authenticates the credential against the actor before repository and
pull-request access, then checks it again around the commit push and
status-reply write boundaries. An identity mismatch or mid-operation rotation
fails closed.

After the new head is confirmed, it may post one idempotent, bot-marked,
commit-linked reply. The shape is deliberately modest:

> 🤖 **Localize Guardian:** Applied a validated translation-only correction in
> the linked commit. The review thread remains open for reviewer confirmation.

The hidden idempotency marker prevents duplicate replies after a crash, but the
marker alone is never trusted. Recovery accepts it only when the numeric actor
ID/type, full canonical body, comment ID-derived URL, publication evidence, and
current PR authority all match. A foreign, altered, or duplicate marker fails
closed instead of suppressing a genuine reply. A reply claims only what the
deterministic checks and confirmed commit establish.

## Closed pull-request backfill and remediation

Closed-PR processing is disabled unless a repository has an explicit
`closed_pr_backfill` block. Each poll finishes the open-PR phase across the
configured repositories first. Closed history is then traversed newest first in
durable scan cycles. A cycle freezes both its UTC start as an upper bound and
its `lookback_days` cutoff as a lower bound. Every later poll restarts at GitHub
page 1 and skips exact pull ID/number pairs in an append-only per-cycle seen set;
it does not persist a mutable pagination position as discovery progress. Before
reporting the cycle complete, the reader performs a second identity-only
traversal and requires it to contain no uncovered eligible pull. This catches
page shrink, insertion, and equal-timestamp reordering that the two traversals
actually observe.

GitHub's REST listing is not an atomic snapshot. Completion therefore requires
a quiescent, bounded discovery-and-confirmation pass; it is not a claim that no
concurrent mutation could occur outside the two observed traversals. A later
cycle rechecks the window and can discover such a change.

Each discovery or confirmation traversal is limited to 100 numeric pages and
10,000 list entries. If either traversal cannot reach the frozen cutoff or the
end of the list within that ceiling, the poll fails visibly and keeps the cycle
incomplete; narrow `lookback_days` before retrying such a high-volume window.
Within that ceiling, while its dependencies succeed, and once the listing is
quiescent long enough for confirmation, repeated polls cover the full frozen
window even when earlier entries are ineligible or already complete. Hydration
remains separately bounded to `max_prs_per_poll` eligible pull requests for that
repository. The strict configuration ranges are 1–3650 days and 1–100 pull
requests per poll.

A non-authentication GitHub failure while hydrating one pull is retried up to
three times immediately. After the third failure, the error is recorded and the
identity is skipped for the rest of the current cycle, so one persistently
malformed pull cannot starve older history. The durable pending retry is
prioritized on later polls independently of the discovery window until it
succeeds or an operator explicitly vetoes it. Authentication failures abort the
poll and do not advance the affected work.

The frozen upper bound and lookback cutoff govern discovery of new closed-PR
evidence only. At most one durable pending branch-only remediation batch is
selected for direct reconciliation in a repository poll. Its exact source pull
identities must fit within `max_prs_per_poll`, but reconciliation uses immutable
stored evidence and the exact remote branch/PR identity; it does not claim to
rehydrate every source before inspecting an already-created remote artifact.
Direct recovery ignores the discovery window, so durable pending work or an
already-published branch cannot age out before reconciliation. When a fresh
candidate is required, the whole source group enters the durable priority
hydration path ahead of ordinary discovery, even when those sources are now
older than `lookback_days`; each source must still match its exact identity,
remain closed, and satisfy current policy and trust eligibility.

If any recovery source cannot be hydrated after its three immediate attempts,
the whole group is deferred for the rest of the current cycle and no partial
candidate is published. This temporary deferral is not the explicit,
terminal-local-skip `remediation quarantine` action. A persistent operator-only
conflict likewise gets only this bounded recovery path before its sources
advance for the current cycle, allowing older history to continue. A later
cycle can reconsider the batch. Malformed,
ambiguous, duplicate, or mismatching remote PR metadata fails closed and remains
visible to the operator. This deliberately favors publication safety and
backlog fairness over automatic liveness.

After a cycle reaches the cutoff or end of the closed list, the next poll starts
a fresh cycle at the newest page. This periodic rescan can discover an edit or
deletion of exact authorized feedback even when the closed pull request's head
SHA and top-level `updated_at` did not change. Feedback authority is a
point-in-time poll snapshot: an edit or deletion observed by a later scan causes
a recheck, but cannot retroactively revoke a remote mutation that has already
begun. Untrusted comment churn and other unrelated update noise do not
invalidate a completed assessment. Both eligible merged and unmerged closed
pull requests are covered; the same configured PR, head-repository, head-owner,
branch, reviewer/bot, and locale authorization still applies.

A historical pull request and its review feedback are evidence only. The
Guardian materializes historical revisions through a read-only checkout and
never applies or publishes a historical branch. It separately captures the
configured repository's exact current base SHA and builds fresh current source
and target evidence. A historical correction is actionable only when the
reported defect independently exists on that current base and the proposed
value passes today's deterministic localization policy. This rule is the same
for merged and unmerged history: an old comment cannot authorize a stale or
unrelated change. If the finding is already fixed or otherwise obsolete on the
configured current base branch, the Guardian records a terminal no-action
checkpoint and publishes nothing. Compatible current-base fixes may share one
batch; conflicting proposals for the same target, ambiguous evidence, and
other unsafe cases remain deferred.

An authorized, still-valid finding that is uncovered and selected for
remediation is published only through a new bot-marked, ready-for-review correction PR
against the configured current base. That PR contains a signed commit and
links to the closed source PR and validated feedback. The Guardian leaves the
historical PR and its branch untouched. This translation correction is separate
from any optional pipeline-prevention proposal.

`observe` and `prepare` perform no GitHub writes for closed-PR work. `observe`
records the bounded assessment and completion checkpoint. `prepare` may also
validate eligible replacements in the disposable current-base checkout, with
the same non-reviewable local outcome described above. Historical recurrence
candidates may contribute to prevention analysis in `propose-prevention`, but
that remains subject to the separate `prevention` policy and publication cap.
A nested remediation policy may remain configured while either read-only mode
keeps it dormant; changing mode is the authority ceiling and does not require
editing the repository policy.

Publishing a historical correction requires all of the following: mode
`apply-owned-translations` or `propose-prevention`; an explicit nested
`closed_pr_backfill.remediation` policy; a positive
`max_remediation_drafts_per_run`; and the write-mode signing and credential
setup. No `prevention` block is required in `apply-owned-translations`. Keep
`max_remediation_drafts_per_run: 0` as the report-only and remediation
kill-switch setting; zero is also the schema default. The Guardian combines
compatible current findings into at most one remediation batch per repository
per poll.
`max_remediation_drafts_per_run` is a separate global per-poll cap shared across
repositories; it does not increase model-call demand because the history
assessment already produced the candidate.

The remediation policy names one exact numeric-ID `push_repository`, a
`push_branch_prefix`, and one typed numeric-ID `publication_actor`. The
publication actor must have API type `User` and must be the same identity as the
repository's top-level ordinary publication actor. It is independent of
`allowed_pr_authors`, which grants authority to advance existing PR branches.
The push repository must already appear in
`allowed_head_repositories`, and `allowed_branch_globs` must contain the
literal `push_branch_prefix` followed by `*`; a broader pattern alone is not
enough.
The actual generated branch—the prefix followed by a deterministic 64-character
lowercase hexadecimal identity—is checked against the allowlist again at
publication time. Use a dedicated ordinary Guardian-owned head scope such as
`localization/guardian-remediation-*`, and ensure the GitHub credential can
create the resulting pull request. An unexpected existing ref, repository
identity, or branch fails closed.

Every remediation broker session resolves the credential's authenticated
GitHub actor. Its immutable numeric ID and API type must match the configured
`publication_actor`, and any created or recovered pull request must name that
same actor as its author and retain the exact generated title and body. The
publication actor's login is a display and audit label only; an actor change,
rewritten draft text, or a different allowlisted author fails closed.

For an actionable batch, the Guardian revalidates the exact current target base
and push repository, creates a signed commit on the deterministic new branch,
and opens a new bot-marked pull request ready for human and automated review. The exact
`[Localize Guardian bot]` title prefix and body text identify it as
bot-generated; this marker is not a GitHub label. Before creation it performs a
coherent sequential pass: after local preparation it rechecks the destination
actor, repository IDs, base SHA, candidate branch, and duplicate-PR state, then
revalidates exact source authority as the final remote observation before the
POST. GitHub's independent REST resources cannot provide an atomic snapshot;
later changes are detected by the next bounded poll and never make an earlier
observation retroactively atomic. It never reopens, edits, or comments on a
closed pull request, never advances its branch, and never merges the remediation
draft.

Append-only publication phases, the deterministic branch, an embedded evidence
marker, and preserved private durable state provide crash recovery without
creating a duplicate branch or draft. Recovery requires the canonical GitHub
URL, publication actor, head and base identities, candidate commit,
`maintainer_can_modify: false`, exact generated title, and full generated body
including the embedded marker, except for the bounded untrusted annotation
described above. Current open-draft, open-ready, closed-unmerged,
and merged states are accepted when all of that metadata remains exact;
malformed or rewritten metadata and ambiguous or duplicate remote identities
fail closed. The Guardian never rewrites or reopens the PR.

Each reconciliation appends an `exact`, `not_found`, or `conflict` remote
observation to the private ledger. An exact merged observation and its terminal
`merged` resolution are recorded atomically so lifecycle and coverage cannot
disagree. `not_found` means the bounded exact lookup completed without a match;
authentication, transport, and malformed-response failures remain failures and
never manufacture absence.

An already-created exact PR remains recoverable after ordinary target-base
advancement. A correction PR that a maintainer closes without merging is a
human veto and continues to cover its exact edits, so the Guardian records the
closed lifecycle and does not recreate the same correction unchanged. When a
correction is merged, its draft-backed source coverage becomes ineffective. If
the same defect later recurs on a newly validated current base, a new coverage
generation and a distinct remediation attempt may be created.

New remediation branch identities use version 2 and bind the exact remediation
policy digest as well as the attempt's immutable inputs. This prevents a policy
change from colliding with a branch left by an older attempt. Rows migrated
from version 1 retain their original identity calculation and remain
recoverable. If evidence or the target base moves before a branch-only attempt
has an exact PR, the Guardian marks that local attempt abandoned, leaves any
remote branch untouched, and durably retries its source group. Fresh validation
can then create a distinct attempt; no overwrite or branch deletion is used.
Unexpected remote content or identity still defers instead of being adopted.

Deduplication is semantic rather than tied to a comment revision. An exact edit
is identified by path, key, current source value, expected target value, and
proposed target value; its target identity is the path-and-key pair. An exact
edit covered by an open or human-closed-unmerged Guardian correction PR is
removed from a mixed batch, while uncovered edits may proceed. Merging that PR
ends its draft-backed suppression, allowing a later independently revalidated
recurrence to receive a new coverage generation. A different edit aimed at the
same target identity conflicts and is deferred instead of opening a competing
PR. Pending exact edits proceed only through their grouped, bounded recovery
path.

Discovery progress is also append-only and compare-and-swap protected for the
exact repository identity and policy digest. A stale concurrent progress writer
fails closed. A crash before an exact pull identity is marked seen safely
rehydrates it on the next restart-from-page-one pass; immutable completion
checkpoints keep already-finished model work idempotent. Completion binds the
pull identity, relevant pull and changed-file
evidence, canonical current source and target content, exact authorized feedback
revisions, authority scope, and policy digest. Editing or deleting an authorized
reviewer/bot item causes a recheck after a later scan observes that revision,
while unrelated or untrusted comment noise does not. Changes to the Guardian
policy or to the trusted pipeline config-and-glossary bundle—whether sourced
from the exact current base or the private operator snapshot—also start an
independent scan and make prior work eligible for reassessment. Unchanged
completed work is skipped within a cycle.

## Recurrence and prevention

Repeated feedback can indicate a one-off translation problem, project policy,
pipeline validation defect, prompt weakness, or an ambiguous case. The model may
classify a recurrence candidate, but it cannot modify the running installation.

With `propose-prevention`, prevention authoring happens in a separate disposable
workspace without GitHub write or signing credentials. A prevention change is
eligible only when it is within the configured pipeline paths, cites immutable
feedback evidence, and includes a focused regression test that is failing on the
base revision and passing with the draft. The controller runs each configured
test argv with a minimal, credential-free environment and prepends the exact
operator-supplied `sandbox_argv_prefix`. This field is deliberately a one-item
argv containing one absolute, directly invoked sandbox-wrapper executable. Put
the confinement policy inside that inspected wrapper; a policy or helper-script
path supplied as another unchecked prefix argument is rejected. Before every
focused command, a runtime probe must be able to read and
write generated paths inside the test workspace
while reads and writes of generated paths outside it are denied. It also
requires denial of an AF_INET loopback bind and a connection to a live parent
loopback canary, plus denial of a filesystem AF_UNIX canary connection when the
platform supports it. On Linux it also requires denial of a write-open on the
parent cgroup's `cgroup.procs`, which would otherwise let a same-user test
process leave its recursive kill scope. A failed probe rejects the prevention
candidate. This focused probe does not prove the policy's behavior for every
host path or network route; the operator still owns and maintains the OS sandbox
policy.
The parent Guardian process must be allowed to create those local canaries; a
host policy that blocks their creation also fails prevention closed.

Exact Git checkouts do not contain ignored project virtual environments. Every
`focused_test_argv` should therefore start with an operator-controlled absolute
interpreter or test executable outside the repository. The sandbox policy must
permit that executable, the Guardian's Python used by the probe, their required
runtime libraries, and the disposable workspace—without granting broader host
or network access.

The Guardian pushes only the bounded signed branch needed to open a pull
request ready for review; it does not merge or deploy that proposal. Immediately
before a branch push or draft-creation POST, it checks the live poll lease and
consumes a non-refundable per-poll publication slot. A lost response therefore
does not make that slot available to another prevention mutation. Runtime
defaults cap prevention at one draft publication workflow across the entire
poll, shared by all repositories and feedback runs. Despite the configuration
key's `max_prevention_drafts_per_run` name, the counter is not reset per feedback
run.
The report-only example pins the cap to zero. `propose-prevention` always requires
an explicit `prevention` block for every monitored repository. A zero cap is a
prevention-publication kill switch: recurrence candidates are skipped, although
that mode still retains the translation-write authority described above.

The prevention target may be a different repository from the monitored
translation project. The prevention block pins target and push repositories by
full name and numeric ID, the exact target base branch, the push branch prefix,
a typed numeric-ID `publication_actor`, code/test path allowlists, and focused
test commands. The actor login is mutable, human-readable audit metadata; the
exact numeric ID and GitHub `User` type grant authority. Every prevention REST session
authenticates `GET /user` and fails closed unless that identity matches, and a
created or recovered pull request must have the same author identity. The
nested actor must also match the repository's top-level ordinary publication
actor so one poll never changes GitHub identity between write paths. Every
block must state `private_target_model_opt_in`. If the exact target base is
private, its code is sent to the authoring model only when that field is `true`;
use `false` for a public target. The monitored translation repository's
`private_repo_model_opt_in` governs its review evidence and does not grant
consent for a different private prevention target. If both are private, both
opt-ins are required.

Prevention policy collections have finite parser and runtime bounds: at most
100 code globs, 100 test globs, 64 focused commands, 256 arguments in each
focused command, and exactly one sandbox-wrapper executable in the sandbox
prefix. Every string in those collections is at
most 4096 UTF-8 bytes, `max_changed_files` is at most 100, and
`push_branch_prefix` must leave 77 characters for the generated
`<base-prefix>-<evidence-hash>` identity inside a 255-character branch name.
The canonical source-policy and maximum test-result attestations must each also
fit 512 KiB, so a configuration that combines many individually maximal strings
can still fail closed before a model or test starts.
Codex output may contain at most 100 recurrence candidates with at most 100
evidence feedback IDs each. Newly generated prevention titles are at most 120
Unicode characters and 256 UTF-8 bytes; bodies are at most 60 KiB. When a
human-facing evidence, path, or command list would exceed its section budget,
the body includes a deterministic omitted-item count and full-list fingerprint
instead of cutting through a Unicode character or Markdown item.

Do not use prevention PRs for project terminology or locale style that belongs
in the consuming project's own config or glossary.

Prevention recovery also requires the canonical GitHub URL; exact generated
title and Guardian-authored body including its marker; exact head, base, and candidate; and
`maintainer_can_modify: false`. Ready-created PRs, untouched legacy open drafts,
their one-way draft-to-ready transition, and a terminal close-unmerged from either
draft or ready state are accepted. A reopen, redraft, rewritten metadata, or over-bound
event history fails closed and is never adopted as Guardian-owned state.

## Durable state, budgets, and recovery

The Guardian keeps local SQLite state. Each authorized feedback content change,
and each observation of that feedback against a distinct PR head/base revision,
becomes a new immutable revision tied to repository, PR, feedback object,
author numeric identity, body hash, head SHA, and base SHA. Runs, terminal
actions, health, recorded token usage, and recorded cost remain auditable across
restarts. Publication phases and marked replies have dedicated reconciliation
and deduplication records.

This is not whole-run exactly-once execution. A successful assessment is cached
against its exact evidence, head/base revisions, model, and effort before its
call completes in the ledger. A process death while a call is in flight leaves
that reservation committed. Without a cached result, a later run can repeat an
ambiguous model attempt and consume another call slot. In API-key mode it may
also incur another charge. Prevention authoring is likewise bounded but is not
replayed from an assessment cache. Treat limits as start-call guards and inspect
the local ledger after recovery; API-key operators should also compare it with
provider billing.

After `raw_retention_days`, raw comment-body rows are logically deleted from the
active SQLite tables; their body hash and revision metadata remain. SQLite
freelists, WAL files, filesystem snapshots, and backups can retain older bytes,
so this setting is not a secure-erasure guarantee. Protect the state directory
and apply the operator's storage-retention policy to it and its backups. Do not
publish it.

`max_model_calls_per_day` is the UTC daily model-call start limit in both
authentication modes. Every assessment and prevention-authoring attempt first
reserves one durable slot atomically. Completed, active, and unknown calls count;
an attempt proved not to have started is cancelled and does not count. The cap
limits Guardian starts, but it is not a ChatGPT-plan guarantee: other Codex use
shares the operator's plan allowance, and provider limits remain authoritative.
The report-only starter sets the cap to two, enough for one assessment with its
single retry; raise it only from observed workload and allowance data.

The configured cap must at least fit every retry for one assessment. In
`observe`, `prepare`, and `apply-owned-translations`, it requires:

```text
max_model_calls_per_day >= max_attempts
```

When `propose-prevention` has a positive draft cap, the cap must leave capacity
for an assessment plus every allowed prevention authoring draft, at every
allowed attempt:

```text
max_model_calls_per_day >= max_attempts *
                          (1 + max_prevention_drafts_per_run)
```

This is a configuration-coherence minimum, not reserved capacity for the whole
poll. A poll can discover multiple assessments, and prior or earlier calls on
the same UTC day can exhaust the cap; remaining work then defers. Each feedback
run separately has a value-edit limit, while the prevention-publication cap is
shared across the whole poll.

Only API-key mode enables `daily_cost_limit_usd` and
`model_call_reservation_usd`. The daily value is the local UTC threshold for
starting another API-billed model attempt, not a provider billing cap. Every
started attempt gets its own conservative cost reservation. A call already in
flight can finish above the threshold, and usage without a reliable price keeps
the reservation as unknown spend. Check provider billing separately,
especially after model-price changes.

For API-key `propose-prevention`, the cost limit must cover the same worst-case
retry shape:

```text
daily_cost_limit_usd >= model_call_reservation_usd *
                        max_attempts *
                        (1 + max_prevention_drafts_per_run)
```

For example, one draft, two attempts, and a `$5` reservation require a daily API
cost limit of at least `$20`, plus a call cap of at least four. These are
conservative start reservations, not predictions or provider limits.

A crashed or interrupted translation publication or marked reply is reconciled
against the fresh PR head and its durable publication record before any retry.
Pending prevention publication is reconciled against the exact target base and
branch state. Other work may be assessed again after a crash as described
above. Never delete the state database merely to make a pending action
disappear.

## Daily launchd schedule on macOS

Stage the user agent only after a clean manual report-only run:

```bash
localize guardian install --config "$GUARDIAN_CONFIG"
```

The generated launchd property list and wrapper contain absolute paths and no
credentials. `RunAtLoad` plus a conservative `StartInterval` wakes the wrapper
periodically; persistent state records the start of each poll attempt and uses
top-level `schedule.hour` (0-23) and `schedule.minute` (0-59) to decide whether
the once-daily run is due in the machine's local wall-clock time. The default
is `00:00`, preserving earlier behavior. A private process lock in the
config's state directory prevents a manual run and scheduler wake from starting
overlapping polls;
scheduled lock contention exits successfully while a manual caller receives a
clear already-running error. This provides catch-up after sleep,
logout, or a missed wall-clock time without running the full model workflow
every interval. A failed scheduled attempt is not retried on the next 15-minute
wake; use an explicit manual `guardian run` after diagnosing it. Manual runs
always execute and become that local day's latest attempt checkpoint.

`install` stages the files but does not load the LaunchAgent. The generated
runner is an operator-local artifact beside the external Guardian config, not a
file to commit to the monitored project or this pipeline repository. If staging
fails, installation removes only regular files created by that attempt and
preserves pre-existing logs or artifacts. Inspect the printed property-list,
wrapper, state, and log paths before loading it explicitly. Run
`localize guardian status --config "$GUARDIAN_CONFIG"` after the first launchd
wake. Re-run `doctor` after CLI, model, authentication, credential, signing, or
policy changes. If the ChatGPT session expires or is revoked, run
`guardian login` again before the next scheduled poll.

## Operator checklist

- Guardian config and credential helpers are outside monitored repositories.
- Operator-sourced pipeline configs use a private `0700` Guardian directory and
  current-user, non-symlink `0600` config and glossary files.
- Every repository, target base branch, PR author, head owner, head branch,
  path, locale, reviewer, and bot constraint is explicit.
- Project plugins are not expected to run inside the Guardian process.
- Numeric IDs came from the GitHub API, not a displayed login.
- Private-repository model access is either disabled or deliberately approved.
- `observe` evidence and `prepare` audit outcomes were reviewed before enabling
  writes; `prepare` was not mistaken for a retained diff preview.
- The directly invoked prevention sandbox wrapper embeds and enforces its policy,
  was tested outside the Guardian, and passes Guardian's focused confinement
  probe.
- Linux deployments provide a delegated cgroup-v2 parent, and `doctor` proves
  that detached descendants are included in its cleanup scope.
- Every prevention test command uses an absolute operator-controlled executable
  outside the exact checkout.
- Every private source repository and private prevention target has its own
  deliberate model-processing opt-in.
- Daily model-call limits, retries, timeouts, edit caps, retention, logs, and
  backups are appropriate for the operator. API-key operators additionally
  reviewed the USD reservations and provider billing.
- Signed commits and the bot-marked status reply were verified on a test PR.
- No workflow expects the Guardian to merge or resolve a review thread.
