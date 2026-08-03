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

## Publication Boundary

Repository implementation and merge do not authorize publishing a manifest,
promoting a channel, revoking a version, rotating a key, or releasing binaries.
Development progress notes are approval-free, but cannot authorize or replace
those operations or a public announcement.

