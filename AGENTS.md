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
signed test-channel promotion, GitHub Pages deployment, live verification, and
isolated real-client acceptance as one operation. Do not ask for another exact-
payload or per-version approval between those steps. This exception does not
authorize stable or mandatory distribution, public Web changelog publication,
Discord announcements, key rotation, revocation, or unrelated production
operations.
