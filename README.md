# BMS-IR Arena patch server

Static, signed update publication for the portable BMS-IR Arena launcher.
This repository does not install a service or an application. Its output is a
directory that can be hosted by an ordinary HTTPS static file server.

Each channel and platform has one mutable pointer and immutable release data:

```text
channels/test/windows-x64/manifest.json
channels/test/windows-x64/history.json
channels/test/windows-x64/manifests/0.4.14.json
channels/test/windows-x64/releases/0.4.14/BMS-IR Arena Test.exe
channels/test/windows-x64/releases/0.4.14/Arena-oraja.jar
channels/test/macos-arm64/manifest.json
channels/test/macos-arm64/history.json
channels/test/macos-arm64/manifests/0.4.14.json
channels/test/macos-arm64/releases/0.4.14/BMS-IR Arena Test.app/Contents/MacOS/bmsir-arena-launcher
```

`history.json` is a signed, append-only index of every version ever drafted
for that channel/platform (`{version, published_at}` pairs, newest first).
`draft` creates or updates it automatically; an existing entry's
`published_at` can never change once recorded, so the index cannot silently
rewrite when an older release actually shipped. Nothing is ever removed from
it. `audit` requires it to exist and to already list the channel's current
version.

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

The repository's GitHub Pages site serves the generated tree at
`https://tenp0312-dev.github.io/bms-ir-arena-patch-server/`.

Normal releases use a delta upload. Keep the locally generated `dist/` tree
complete and append-only, run the exact audit, then package only the platform
pointers that changed:

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
versioned manifest, and artifact hashes. It writes an archive containing only
that version's pointer, signed history, versioned manifest, and artifacts. The
output must be outside `dist/` so it cannot contaminate the exact publication
tree.

Create the checked pre-release and upload the small delta, then manually
dispatch `Deploy signed test-channel delta`:

```sh
gh release create test-0.4.14.36 \
  --repo tenP0312-dev/bms-ir-arena-patch-server \
  --prerelease \
  --title "Arena internal test 0.4.14.36"
gh release upload test-0.4.14.36 \
  ../bmsir-arena-test-channel-0.4.14.36-delta.tar.gz \
  --repo tenP0312-dev/bms-ir-arena-patch-server
```

Use these workflow inputs:

- `base_release_tag`: the previous successfully deployed release tag
- `base_asset_name`: its complete snapshot name, without `.partNNN`
- `release_tag`: the new release tag containing the delta
- `delta_asset_name`: the uploaded delta name, without `.partNNN`
- `snapshot_asset_name`: the complete snapshot name to create for this release

The workflow downloads the previous complete snapshot inside GitHub, audits it,
and accepts the delta only when each changed platform strictly prepends exactly
one signed history entry. It rejects history rewrites, immutable path
overwrites, missing files, symlinks, special files, and every extra path. It
then audits the reconstructed complete tree, creates deterministic 1,900 MiB
snapshot parts on the runner, and stores those parts on the new Release. The
verified Pages tree is deployed before that recurring multi-gigabyte archive
upload, so snapshot retention does not delay the client update. A retry accepts
an existing snapshot part only when its bytes are identical. The new release and its unsuffixed
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

`Deploy complete signed test-channel snapshot (seed or rollback)` is not the
normal release path. Use it only to install the first trusted base snapshot or
to redeploy a complete archived snapshot during rollback. Do not rebuild and
upload the multi-gigabyte complete snapshot from an operator machine for each
release; the delta workflow owns that recurring work. The existing
`test-launcher-0.2.21` complete snapshot can seed the first delta deployment.

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
