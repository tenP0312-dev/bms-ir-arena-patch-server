# BMS-IR Arena patch server

Static, signed update publication for the portable BMS-IR Arena launcher.
This repository does not install a service or an application. Its output is a
directory that can be hosted by an ordinary HTTPS static file server.

Each channel and platform has one mutable pointer and immutable release data:

```text
channels/test/windows-x64/manifest.json
channels/test/windows-x64/manifests/0.4.14.json
channels/test/windows-x64/releases/0.4.14/BMS-IR Arena Test.exe
channels/test/windows-x64/releases/0.4.14/Arena-oraja.jar
```

The manifest is canonical JSON signed with Ed25519. Every artifact path,
SHA-256, size, channel, platform, mandatory flag, minimum launcher version,
revocation list, and release note is covered by the signature. Artifact paths
are relative and release directories are immutable.

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
  --version 0.4.14 \
  --notes-file release-notes.md \
  --artifact "BMS-IR Arena Test.exe" \
  --artifact Arena-oraja.jar

bmsir-arena-patch verify \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifests/0.4.14.json \
  --public-key public/test.pub

bmsir-arena-patch promote \
  --root dist \
  --manifest dist/channels/test/windows-x64/manifests/0.4.14.json \
  --public-key public/test.pub
```

`rollback` repoints the channel to a verified older versioned manifest.
`revoke` adds a version to the signed revocation list and makes the channel
mandatory. Both operations still require an explicit operator command.

For local testing:

```sh
bmsir-arena-patch serve --root dist --port 8765
bmsir-arena-patch probe \
  --url http://127.0.0.1:8765/channels/test/windows-x64/manifest.json \
  --public-key public/test.pub \
  --channel test --platform windows-x64 \
  --current-version 0.4.13
```

## BMS-IR test-channel hosting

The BMS-IR backend serves the generated tree from its untracked
`tools/lr2ir_compat_data/arena_patches` directory at
`https://www.bms-ir.org/new/arena/patches/`. Copy the complete generated
`dist/` contents there only after `verify` and `promote` succeed. The source
repository, public download page, and changelog do not contain or link the
internal test artifacts.

The configured internal launcher is compiled with that HTTPS base URL and the
matching disposable test public key. Keep the private key outside every Git
worktree. Replacing the test key requires rebuilding the test launcher and the
entire signed channel; a manifest signed by a different key fails closed.

## Publication boundary

Internal test manifests may use a disposable test key and unsigned launcher
binary. Public stable publication needs a separately approved production
Ed25519 key and Authenticode-signed Windows executable. This repository does
not contain production credentials, upload destinations, or deployment steps.
