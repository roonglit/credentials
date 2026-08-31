# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for 2.0.0

Removing the legacy reader is the breaking change that earns a major bump, and
under Go's semantic import versioning it also renames the module path to
`github.com/roonglit/credentials/v2`. Before cutting it:

- run `credentials migrate` everywhere and commit the results
- set `CREDENTIALS_ALLOW_LEGACY=0` in CI so a file cannot regress

By then no file is on the old format and the import rewrite is the only work.

## [1.1.0] - 2026-08-31

Credentials are now sealed with authenticated encryption. **Upgrading requires
no code changes and no migration** — old files still open, and the exported API
is unchanged.

### Security

- Credentials are sealed with **AES-256-GCM** instead of AES-CFB. CFB is
  unauthenticated: decryption is `P[0] = C[0] XOR E(IV)`, so anyone able to
  write `credentials.yml.enc` could flip a chosen plaintext bit without holding
  the master key, and nothing detected it. Since the file is committed to git and
  copied into images, write access is not a high bar. Go's standard library now
  marks CFB deprecated for the same reason.
- The on-disk format is `CREDS-v2 || nonce(12) || GCM(plaintext)`, with the
  magic passed as additional authenticated data so a v2 file cannot be
  downgraded without failing authentication.
- The master key is validated as exactly 32 bytes. `aes.NewCipher` accepts 16
  and 24, so a truncated key previously downgraded to AES-128 in silence.
- `GenerateMasterKey` refuses to overwrite an existing key, which would have
  made the encrypted file permanently unreadable.

### Added

- `credentials show` — print the decrypted contents. It was advertised in the
  usage text but never implemented.
- `credentials migrate` — re-encrypt an old file in the current format without
  opening an editor, for hosts and CI with no terminal to attach.
- `CREDENTIALS_DIR` selects the config directory; `CREDENTIALS_ALLOW_LEGACY=0`
  selects strict mode, where an unmigrated file is an error rather than a warning.
- Exported `GenerateMasterKey` and `ReadMasterKey`.
- `ConfigReader.AllowLegacy` and `ConfigEditor.AllowLegacy`.

### Changed

- Reads accept both formats; **writes are always in the current format**, so any
  save migrates a file. Reading a legacy file warns once per path, naming the
  file and the command that fixes it permanently.
- The editor resolves `$VISUAL`, then `$EDITOR`, then `vi`, instead of being
  pinned to `vim`.
- Environment overrides return parse errors rather than skipping them. A
  malformed `ACCESS_TOKEN_DURATION` previously left the field zeroed and let the
  process boot as though it had never been set. `uint`, `float` and
  `[]string` are now supported.
- `ConfigReader.Read` uses a private viper instance rather than the package
  singleton, which two readers — or two parallel tests — used to overwrite.
- `ReadMasterKey` trims surrounding whitespace, so a key written with `echo` or
  piped through `base64 -d` in a Dockerfile no longer fails with an opaque hex
  error.

### Fixed

- The reader carried its own second copy of the decryption routine. A change to
  one could silently diverge from the other and surface only as a boot failure.
  There is now one decryption path in the package.
- Replaced `io/ioutil`, deprecated since Go 1.16.

### Tests

Round-trip, tamper detection at four offsets, wrong key, wrong key length,
legacy compatibility, the refuse-then-migrate path, editor-to-reader end to end,
and `TestV1APIStillCompiles`, which exercises the exact surface downstream
consumers use so a future change cannot break it silently.

## [1.0.0] - 2024-11-12

Initial release: encrypted credentials file, master key, `credentials edit`, and
a reader that unmarshals into a user-supplied struct with environment overrides.

[Unreleased]: https://github.com/roonglit/credentials/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/roonglit/credentials/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/roonglit/credentials/releases/tag/v1.0.0
