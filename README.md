# BMS-IR Arena patch server

Static, signed update publication for the portable BMS-IR Arena launcher.
This repository does not install a service or an application. Its output is a
directory that can be hosted by an ordinary HTTPS static file server.

Each channel and platform has one mutable pointer and immutable release data:

```text
channels/test/windows-x64/manifest.json
channels/test/windows-x64/history.json
channels/test/windows-x64/artifact-locations.json
channels/test/windows-x64/manifests/0.4.14.json
channels/test/macos-arm64/manifest.json
channels/test/macos-arm64/history.json
channels/test/macos-arm64/artifact-locations.json
channels/test/macos-arm64/manifests/0.4.14.json
channels/test/macos-arm64/releases/0.4.14/BMS-IR Arena Test.app/Contents/MacOS/bmsir-arena-launcher  # explicitly retained compatibility file
```

`history.json` is a signed, append-only index of every version ever drafted
for that channel/platform (`{version, published_at}` pairs, newest first).
It may also carry a signed `latest_launcher` pointer containing the release
version and maximum launcher version. New launchers use that pointer to fetch
only the selected versioned manifest; older launchers ignore the additive
field and continue their complete signed-history scan.
`draft` creates or updates it automatically; an existing entry's
`published_at` can never change once recorded, so the index cannot silently
rewrite when an older release actually shipped. Nothing is ever removed from
it. `audit` requires it to exist and to already list the channel's current
version.

An optional signed `artifact_locations` history reference points new launchers
to `artifact-locations.json`. That independently signed per-platform index
binds an external artifact's version, installation path, SHA-256, size, and
flat HTTPS GitHub Release asset URL. A location may explicitly retain the same
verified bytes on Pages for legacy-launcher compatibility. Unindexed legacy
artifacts keep their Pages-relative behavior. If history advertises the index,
an invalid signature, target, URL, duplicate, or manifest mismatch fails
closed.

The manifest is canonical JSON signed with Ed25519. `artifacts` is the sparse
delta for the current version. An optional `bootstrap` contains an HTTPS ZIP
URL, ZIP size and SHA-256, and the full installation inventory used only when
the launcher is in an empty directory. Every artifact path, SHA-256, size,
channel, platform, mandatory flag, minimum launcher version, optional latest
`launcher_version`, revocation list, Japanese/English release notes, and
announcement list is covered by the signature. When `launcher_version` is
present, the same sparse release must carry the matching Windows launcher EXE
or macOS launcher executable so a body-current installation can still receive
the launcher independently. Artifact paths are relative and release
directories are immutable. Older manifests without `launcher_version`, or
with only `release_notes_markdown`, remain valid.

Player profiles, BMS data, replays, score databases, configuration files, the
local version marker, staging data, and launcher backups are rejected as patch
artifacts. The launcher writes its version marker only after a complete,
verified transaction, and restores replaced program files if installation
fails.

## Operator flow

Before promoting a channel pointer that adds or replaces a BMS-IR-built body
or plugin, complete the paired server gate sequence in `BMS-Mania/IR`'s
`docs/PRODUCTION_VPS_OPERATIONS.md`. This applies to internal test,
prerelease, sparse, and stable updates: stage the exact final artifacts, add
and verify the ordinary-score body/plugin allowlists and Arena client-version/
build gates where applicable, perform required guarded reloads, and only then
make the artifact downloadable through the launcher. A launcher-only update
has no body/plugin gate to add.

Use a non-production test key for internal builds. Never commit a private key.

```sh
python -m pip install -e .
bmsir-arena-patch keygen \
  --private-key private-keys/test.key \
  --public-key public/test.pub

bmsir-arena-patch draft \
  --root dist \
  --source package/windows \
  --private-key private-keys/test.key \
  --channel test \
  --platform windows-x64 \
  --version 0.4.14.9 \
  --notes-ja-file release-notes-ja.md \
  --notes-en-file release-notes-en.md \
  --announcements-file announcements.json \
  --launcher-version 0.2.20 \
  --bootstrap-manifest previous-windows-manifest.json \
  --bootstrap-archive BMS-IR-Arena-oraja-0.4.14.8-windows-test-java21.zip \
  --bootstrap-url https://github.com/example/releases/download/test-0.4.14.8/BMS-IR-Arena-oraja-0.4.14.8-windows-test-java21.zip \
  --artifact "BMS-IR Arena Test.exe"

bmsir-arena-patch verify \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifests/0.4.14.9.json \
  --public-key public/test.pub

bmsir-arena-patch draft \
  --root dist \
  --source package/macos \
  --private-key private-keys/test.key \
  --channel test \
  --platform macos-arm64 \
  --version 0.4.14.9 \
  --notes-ja-file release-notes-ja.md \
  --notes-en-file release-notes-en.md \
  --announcements-file announcements.json \
  --launcher-version 0.2.20 \
  --bootstrap-manifest previous-macos-manifest.json \
  --bootstrap-archive BMS-IR-Arena-oraja-0.4.14.8-macos-test-java21.zip \
  --bootstrap-url https://github.com/example/releases/download/test-0.4.14.8/BMS-IR-Arena-oraja-0.4.14.8-macos-test-java21.zip \
  --artifact "BMS-IR Arena Test.app/Contents/Info.plist" \
  --artifact "BMS-IR Arena Test.app/Contents/Resources/icon.icns" \
  --artifact "BMS-IR Arena Test.app/Contents/MacOS/bmsir-arena-launcher"

bmsir-arena-patch promote \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifests/0.4.14.9.json \
  --public-key public/test.pub
```

The bootstrap archive is read once while drafting. Every ZIP member must match
the previous full manifest; unknown paths, symlinks, missing files, incorrect
hashes, and missing executable bits are rejected. The archive itself is not
copied into the Pages tree. Its signed HTTPS URL normally points to an
immutable GitHub Release asset.

`rollback` repoints the channel to a verified older versioned manifest only
when that release's immutable files are still in the deployed tree. The Pages
tree keeps every version in signed history for launcher downgrade support, but
operational rollback still redeploys a complete previously archived Pages
snapshot. That restores both mutable pointers and the exact signed history as
one verified unit.
`revoke` adds a version to the signed revocation list and makes the channel
mandatory. Both operations still require an explicit operator command.

`announcements.json` is a newest-first array. Every item requires a real ISO
date and both titles; at most 20 entries are accepted:

```json
[
  {
    "date": "2026-08-03",
    "title_ja": "Arena oraja 0.4.14.4 テスト開始",
    "title_en": "Arena oraja 0.4.14.4 testing is now available"
  }
]
```

Use `--mandatory` only when the installed version must not start. A verified
mandatory decision is cached by the launcher and remains enforced if a later
network check fails. Arena service compatibility remains the final gate for a
client that has never received the mandatory manifest or whose local files
were manually altered.

For local testing:

```sh
bmsir-arena-patch serve --root dist --port 8765
bmsir-arena-patch probe \
  --url http://127.0.0.1:8765/channels/test/windows-x64/manifest.json \
  --public-key public/test.pub \
  --channel test --platform windows-x64 \
  --current-version 0.4.13
```

## GitHub Pages test-channel hosting

Prepare a normal release with one transactional command. The machine-readable
spec names the reviewed source commits, Arena server-gate identity, previous
snapshot, both platform sources, notes, and workflow asset names. Keep the
private-key path out of the spec and use a stable `signing_key_ref` label. The
command derives the private key's public key and compares it with the expected
public-key file before creating any output.

```sh
bmsir-arena-patch prepare-release \
  --spec release-spec.json \
  --base-archive previous-complete-snapshot.tar.gz \
  --private-key /protected/arena-test-current.key \
  --public-key /protected/arena-test-current.pub \
  --output-dir prepared-test-0.4.14.48
```

The command extracts the previous complete or compact snapshot into a new
temporary tree, audits it, drafts and promotes every specified platform with
one timestamp, stages external artifacts under `release-assets/`, signs their
locations, audits the result, creates the signed metadata delta, and only then
atomically exposes the output directory. It writes `release-state.json` with
exact GitHub workflow inputs and artifact identities. A failed key check,
draft, location check, audit, or delta build leaves no reusable partial output.

String entries in `platforms[].artifacts` retain the legacy Pages-relative
layout. Object entries name a unique flat `asset_name` on the release and an
explicit `retain_on_pages` compatibility decision. They require the spec's
`artifact_repository`. After the launcher-first migration, normal releases use
`false`; `true` is reserved for a deliberately reviewed legacy-launcher bridge
because retained entries remain part of every later exact Pages snapshot.
Normal `release_uploads` then contains each external
artifact followed by the signed delta. Upload every listed path to the checked
prerelease before dispatching the workflow. Do not add duplicate standalone
body/plugin assets just for convenience; use `standalone_release_assets` only
when an explicit fallback or direct-download requirement has been reviewed.

Start from `docs/release-spec.example.json`; paths may be absolute or relative
to the spec file.

The repository's GitHub Pages site serves the generated tree at
`https://tenp0312-dev.github.io/bms-ir-arena-patch-server/`.

Normal releases use a metadata delta plus the newly referenced flat Release
assets. Keep the locally generated publication complete according to its
signed locations and explicit compatibility retention, run the exact audit,
then package only the platform pointers that changed:

```sh
bmsir-arena-patch audit \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifest.json \
  --manifest dist/channels/test/macos-arm64/manifest.json \
  --public-key public/test.pub

bmsir-arena-patch create-delta \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifest.json \
  --manifest dist/channels/test/macos-arm64/manifest.json \
  --public-key public/test.pub \
  --output ../bmsir-arena-test-channel-0.4.14.36-delta.tar.gz
```

Pass only the changed platform pointer to `create-delta` when a release changes
one platform. The command verifies signatures, history, the matching immutable
versioned manifest, signed locations, and any retained artifact hashes. It
writes an archive containing the pointer, signed history and locations,
versioned manifest, and only retained compatibility files. External payloads
remain separate Release assets. The output must be outside `dist/` so it cannot
contaminate the exact publication tree.

Create the checked pre-release and upload the small delta, then manually
dispatch `Deploy signed test-channel delta`:

```sh
gh release create test-0.4.14.36 \
  --repo tenP0312-dev/bms-ir-arena-patch-server \
  --prerelease \
  --title "Arena internal test 0.4.14.36"
gh release upload test-0.4.14.36 \
  prepared/release-assets/* \
  prepared/bmsir-arena-test-channel-0.4.14.36-delta.tar.gz \
  --repo tenP0312-dev/bms-ir-arena-patch-server
```

Use these workflow inputs:

- `base_release_tag`: the previous successfully deployed release tag
- `base_asset_name`: its complete snapshot name, without `.partNNN`
- `release_tag`: the new release tag containing the delta
- `delta_asset_name`: the uploaded delta name, without `.partNNN`
- `snapshot_asset_name`: the complete snapshot name to create for this release

The workflow downloads the previous snapshot inside GitHub and accepts the
delta only when each changed platform strictly prepends exactly one signed
history entry and preserves every existing location byte-for-byte. It downloads
and hashes each newly indexed Release asset before applying the delta, and
rejects history/location rewrites, immutable path overwrites, missing files,
symlinks, special files, and every extra path. It then audits and deploys the
reconstructed compact Pages tree, creates a deterministic rollback/next-base
snapshot, and stores it on the new Release. A retry accepts an existing snapshot
part only when its bytes are identical. The new release and its unsuffixed
`snapshot_asset_name` become the base inputs for the next delta.

The delta can also be split if it exceptionally exceeds GitHub Releases'
per-asset limit:

```sh
split -b 1900m -d -a 3 \
  bmsir-arena-test-channel-0.4.14.36-delta.tar.gz \
  bmsir-arena-test-channel-0.4.14.36-delta.tar.gz.part
```

Both workflows accept either one archive asset or contiguous `.part000`,
`.part001`, ... assets when given the unsuffixed archive name. Mixed, missing,
malformed, empty, or inconsistently sized parts fail closed.

### One-time launcher-first compact migration

Publish and verify launcher 0.2.26 or newer through the legacy string-artifact
Pages layout before compacting Pages; do not advertise the index in that first
launcher release. The
migration command refuses a channel without a signed `latest_launcher`
reference, audits the full source tree first, and writes a new output directory
atomically. It never changes or deletes the trusted full source snapshot. Every
historical payload is deduplicated into flat Release uploads; current release
artifacts and the latest launcher-bearing release are automatically and
explicitly retained on Pages so legacy launchers can still update.

```sh
bmsir-arena-patch externalize-publication \
  --root full-publication \
  --private-key /protected/arena-test-current.key \
  --public-key /protected/arena-test-current.pub \
  --repository tenP0312-dev/bms-ir-arena-patch-server \
  --release-tag test-external-artifacts-1 \
  --output-dir prepared-external-migration
```

Create the checked migration prerelease, upload every file listed under
`release-assets/`, and then verify the actual remote bytes before packaging or
deploying the compact snapshot:

```sh
find prepared-external-migration/release-assets -type f -print0 |
  while IFS= read -r -d '' path; do
    gh release upload test-external-artifacts-1 "$path" \
      --repo tenP0312-dev/bms-ir-arena-patch-server
  done

bmsir-arena-patch audit \
  --root prepared-external-migration/publication \
  --manifest prepared-external-migration/publication/channels/test/windows-x64/manifest.json \
  --manifest prepared-external-migration/publication/channels/test/macos-arm64/manifest.json \
  --public-key /protected/arena-test-current.pub \
  --verify-remote
```

Archive that exact audited `publication/` directory as the new complete
snapshot and use `Deploy complete signed test-channel snapshot (seed or
rollback)` once. Retain the pre-migration complete snapshot and its current
Release tags for rollback. Do not repoint or delete the old snapshot until the
compact Pages deployment and both legacy-launcher self-update and index-aware
artifact download have been accepted.

`Deploy complete signed test-channel snapshot (seed or rollback)` is not the
normal release path. Use it only to install the first trusted base snapshot or
to redeploy a complete archived snapshot during rollback. Do not rebuild and
upload a complete snapshot from an operator machine for each release; the delta
workflow owns that recurring work. A pre-migration multi-gigabyte snapshot is a
rollback source, not the base for ordinary post-migration releases.

When a complete snapshot really must be packaged on macOS, set
`COPYFILE_DISABLE=1` so BSD tar does not add AppleDouble `._*` metadata. The
workflows remove only regular AppleDouble sidecars before audit; every other
unsigned path remains a hard failure. Release binaries remain outside Git
history, and the normal public download page and changelog do not link the
internal test channel.

The configured internal launcher is compiled with that HTTPS base URL and the
matching disposable test public key. Keep the private key outside every Git
worktree. Replacing the test key requires rebuilding the test launcher and the
entire signed channel; a manifest signed by a different key fails closed.

## Publication boundary

Internal test manifests may use a disposable test key and unsigned launcher
binary. Public stable publication needs a separately approved production
Ed25519 key and Authenticode-signed Windows executable. This repository does
not contain production credentials, upload destinations, or deployment steps.
