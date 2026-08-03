# Codex Progress Discord Notes

Last updated: 2026-08-03

This repository participates in the shared BMS-IR development progress route.
The route is an informal work log for what Codex is doing, not a public release
announcement.

## Required Flow

For substantial work expected to take more than about five minutes:

1. define an ordered, task-specific phase plan before implementation;
2. send the full plan when the task and initial estimate are understood;
3. send immediately when the current phase changes;
4. send immediately for a material plan change, blocker, error, cancellation,
   or handoff;
5. send a heartbeat every 10 minutes while the same phase continues; and
6. send a final note when all authorized work is complete.

A typical task selects only the phases it needs from investigation, planning,
implementation, build/local validation, pull request/CI, separately authorized
deployment or publication, and completion. Keep one current phase clear. Each
note shows completed, current, and pending phases plus best-effort elapsed and
remaining time. Use an unknown estimate instead of false precision. Time is
metadata; it does not delay phase-change or error messages.

Do not mirror every command. Short tasks need no progress note. Completion must
state test/CI status and whether deployment or publication was completed, not
authorized, or deferred.

## Safety And Authorization

Progress messages require no per-message preview, approval, content hash,
receipt ledger, or identity check. Never include credentials, Webhook URLs,
private host details, personal data, raw logs, private IDs, fingerprints, or
token-bearing links. Mentions stay disabled.

This route cannot request or grant approval and cannot replace a public release
notice. Production deployment, binary publication, changelog publication, and
public Discord announcements retain their repository-specific authorization
rules. A notification failure does not block development unless notification
delivery itself is the requested work.

## Shared Sender

The Webhook URL is stored outside Git at:

```text
~/.config/bms-ir/codex-progress-webhook-url
```

The shared sender is installed outside each worktree at:

```text
~/.config/bms-ir/send_codex_progress_note.py
```

Example:

```bash
python3 ~/.config/bms-ir/send_codex_progress_note.py \
  --task "Repository task" \
  --step "Investigate and define scope" \
  --step "Implement" \
  --step "Validate" \
  --step "Open PR and pass CI" \
  --completed-steps 1 \
  --status "Implementation is in progress" \
  --elapsed "15 minutes" \
  --remaining "about 25 minutes"
```

The canonical sender source and tests are maintained in `BMS-Mania/IR` at
`tools/send_codex_progress_note.py`. A new development host needs the sender
and mode-`0600` route file provisioned locally; neither secret nor host-local
copy belongs in a repository.

