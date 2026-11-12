# AppSleuth progress and TODO

Last updated: 2026-11-12 (items 1-4 of the old list done)

## Done

### Released in 1.5.5 (tag `v1.5.5`, published to PyPI)
- `info` shows Cordova wildcard whitelist entries (`<access origin="*">`, `<allow-navigation href="*">`,
  `<allow-intent href="*">`) as Posture flags and in their own "Cordova whitelist (wildcards)" section below ATS,
  with the exact tag and its line in `config.xml`.
- Android parity: the compiled `res/xml/config.xml` is decoded (also when renamed by resource shrinking), and the
  `assets/www` / `assets/public` web layer is scanned for secrets, source maps and external hosts.
  Tests: `tests/test_cordova_android.py`. Not covered: AAB (protobuf resources); scan the `.apks` from bundletool.
- `info --full` lists every API key and secret found (pattern hits, high-entropy strings, Firebase keys), unmasked.
  Stored as `meta.secrets` in the scan data.
- Wildcard flags added to `diff` risk flags.

### After 1.5.5
- Test fixture for the fake Google key is built from pieces so secret scanners don't flag it (`2bc76ad`).
- Secrets review of the repo and history (TruffleHog + grep): no real secrets; only fake test fixtures.

### Working tree (not yet committed)
- `data --ios`: reads the app's keychain item metadata over SSH (`keychain-2.db`) and shows each item's
  accessibility class (`kSecAttrAccessible...`, including `AlwaysThisDeviceOnly`).
  - Items shown in the terminal, in `report.md`/`report.html`, and saved as `keychain.json` (`--audit-dir` reads it).
  - `Always` / `AlwaysThisDeviceOnly` items are a MEDIUM finding; other classes are INFO.
  - Files: `devdata.py`, `dataaudit.py`, `cli.py`; tests: `tests/test_keychain.py`.
  - Verified on a real iPhone (Alphaniti `com.alphaniti.dev`: 3 items, all AfterFirstUnlockThisDeviceOnly).
  - Limits: values stay encrypted (not shown); only groups containing the bundle id are matched.

### Done since 1.5.5 (uncommitted)
- Exact location per secret: `file:line` (plus `:col` on minified lines) for the Cordova/Capacitor web layer,
  `exe @0xOFFSET` for Mach-O, dex class/method as before. Note: finding fingerprints for these changed, so
  existing ignore-file `fingerprint:` rules for web/Mach-O secrets need regenerating.
- Runtime: per-hook table, coverage warnings, `--dump-events`, hooks for URLSession tasks (Alamofire),
  NSURLConnection, CFNetwork, `connect()`, DNS, SecTrust, challenge delegates, WKWebView.
- Cordova/Capacitor: CSP, `<content src>`, risky preferences/settings, plugin list with versions.
- `data --ios`: keychain values read by default through Frida; cleaner keychain table.
- `--report` flag on every command; no report files are written without it.

### Runtime check on Alphaniti (iPhone, Frida 17.12.0, USB)
- Run completed: hooks loaded (no probe errors), 28 events, 0 findings. Not yet proven that the hooks cover the
  app's networking (see TODO 2).
- Note: `pipx install --force` removes Frida from AppSleuth's environment; re-run
  `pipx inject appsleuth frida==17.12.0` afterwards.

## TODO (priority order)
1. CI output: `scan --fail-on high` exit codes (exists) and SARIF export.
2. Known-vulnerable libraries: optional `sbom --osv` lookup (currently offline only).
3. iOS URL schemes and universal links: fetch `apple-app-site-association` and flag weak handlers.
4. Screen and clipboard exposure: screenshot protection, pasteboard use.
5. `info` output as an HTML or Markdown report, like `scan`.
6. Runtime: positive control with a plain `http://` request through URLSession on a device (the new hooks fire for
   sockets and WKWebView on the iPhone; URLSession `net` events were not yet confirmed live). Android has no
   per-hook call counters yet (iOS agent only).
7. Keychain values: 3 items in `keychain-2.db` (hashed 20-byte names) were not returned by the app's own
   `SecItemCopyMatching` on Alphaniti; cause unknown.

## Release housekeeping
- Next release would be 1.5.6: bump `pyproject.toml` and `appsleuth/__init__.py`, tag `v1.5.6`, create a GitHub
  release (the publish workflow checks the tag against the package version and runs the tests).
- Commit messages and releases carry no Claude co-author line.
