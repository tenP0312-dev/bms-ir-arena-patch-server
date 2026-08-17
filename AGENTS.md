# BMS-IR Arena Patch Server Agent Guide

This repository is the source of truth for signed static update metadata and
publication tooling used by the portable BMS-IR Arena launcher.

## Read First

Read `README.md` and `docs/CODEX_PROGRESS_DISCORD.md` before changing the
repository. Read the tests around any behavior being changed.

## Working Rules

- Preserve unrelated changes and do not use destructive Git commands.
- Use an Issue, scoped `codex/` branch, validation, pull request, and passing
  CI for implementation work.
- Use the configured `gh` CLI from the first request for GitHub write actions,
  including Issues and pull requests. Do not probe the connected GitHub app
  first; its write path for this repository is already known to return `403`.
- Use `apply_patch` for manual edits.
- Never commit private signing keys, production credentials, generated release
  trees, or launcher binaries.
- For substantial work expected to take more than about five minutes, define
  the task phases first. Send progress immediately at phase changes and errors,
  plus every 10 minutes while one phase continues, using
  `docs/CODEX_PROGRESS_DISCORD.md`.
- Run `python3 -m unittest discover -s tests -v` for code changes and
  `git diff --check` for every change.
- Use the signed delta archive and `Deploy signed test-channel delta` workflow
  for normal internal test-channel releases. The workflow-generated complete
  snapshot on each successful Release is the base for the next delta.
- A retention-only delta is a corrective compatibility operation, not the
  normal release path. It may only add an exact already-signed external
  artifact to Pages and change its signed `retain_on_pages` value from `false`
  to `true`; it must not change the channel pointer, history, manifest,
  artifact identity, or external URL.
- Use `Deploy complete signed test-channel snapshot (seed or rollback)` only
  for the first trusted seed or an explicit rollback. Do not make recurring
  operator uploads of the complete append-only publication tree.

## Publication Boundary

Repository implementation and merge do not authorize publishing a manifest,
promoting a channel, revoking a version, rotating a key, or releasing binaries.
Development progress notes are approval-free, but cannot authorize or replace
those operations or a public announcement.

An explicit operator request to distribute an Arena internal `test`-channel
build is the narrow exception. After the exact source and artifacts pass their
required tests, platform builds, signed-manifest/history audit, and artifact
hash/size verification, that request authorizes the checked GitHub prerelease,
signed test-channel promotion, GitHub Pages deployment, and the paired server
gate sequence as one operation. Do not ask for another exact-payload or per-
version approval between those steps.

Every BMS-IR-built body or plugin made downloadable through the launcher is
gate-bound, including internal test builds, prereleases, sparse updates, and
stable releases. Before promoting the signed channel pointer, complete every
applicable ordinary-score body/plugin allowlist and Arena client-version/build
gate, required guarded service reload, and effective check under
`BMS-Mania/IR`'s `docs/PRODUCTION_VPS_OPERATIONS.md`. Use only the exact
artifacts named by the final signed manifest. Local previews, third-party or
unreviewed builds, and launcher-only updates are excluded from body/plugin
gates. Do not report a downloadable but rejected artifact as complete.

Codex must not use Computer Use or launch, activate, focus, or control the
launcher, updater, or game body for debugging or acceptance. Physical client
evidence is operator-run. This exception does not authorize stable or
mandatory distribution, public Web changelog publication, Discord
announcements, key rotation, revocation, or unrelated production operations.
