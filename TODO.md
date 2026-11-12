# AppSleuth progress and TODO

Last updated: 2026-11-12

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

### Not yet committed (working tree)
- `data --ios`: reads the app's keychain item metadata over SSH (`keychain-2.db`) and shows each item's
  accessibility class (`kSecAttrAccessible...`, including `AlwaysThisDeviceOnly`).
  - Items shown in the terminal, in `report.md`/`report.html`, and saved as `keychain.json` (`--audit-dir` reads it).
  - `Always` / `AlwaysThisDeviceOnly` items are a MEDIUM finding; other classes are INFO.
  - Files: `devdata.py`, `dataaudit.py`, `cli.py`; tests: `tests/test_keychain.py`.
  - Verified on a real iPhone (Alphaniti `com.alphaniti.dev`: 3 items, all AfterFirstUnlockThisDeviceOnly).
  - Limits: values stay encrypted (not shown); only groups containing the bundle id are matched.

### Runtime check on Alphaniti (iPhone, Frida 17.12.0, USB)
- Run completed: hooks loaded (no probe errors), 28 events, 0 findings. Not yet proven that the hooks cover the
  app's networking (see TODO 2).
- Note: `pipx install --force` removes Frida from AppSleuth's environment; re-run
  `pipx inject appsleuth frida==17.12.0` afterwards.

## TODO (priority order)
1. **Exact file and line for each secret.** Today the location is coarse (`web assets (www/)`). Show
   `www/js/app.min.js:1423` (or the dex class on Android) in `scan`, `info --full` and the reports.
2. **Runtime event breakdown.** Per-hook event counts and a `--dump-events` option, so "28 events, 0 findings" can
   be understood. Add hooks for stacks likely missed: Alamofire/CFNetwork, `SecTrust` evaluation (pinning),
   WKWebView loads. Then re-run on Alphaniti with a positive control (e.g. a plain `http://` request).
3. **More Cordova/Capacitor config checks.** Missing Content-Security-Policy in `index.html`,
   `<content src="http://...">`, Android `AndroidInsecureFileModeEnabled`, risky `<preference>` values, plugin list
   with versions.
4. Keychain values: decrypt and show via a Frida call on the device (currently metadata only).
5. CI output: `scan --fail-on high` exit codes and SARIF export.
6. Known-vulnerable libraries: optional `sbom --osv` lookup (currently offline only).
7. iOS URL schemes and universal links: fetch `apple-app-site-association` and flag weak handlers.
8. Screen and clipboard exposure: screenshot protection, pasteboard use.
9. `info` output as an HTML or Markdown report, like `scan`.

## Release housekeeping
- Next release would be 1.5.6: bump `pyproject.toml` and `appsleuth/__init__.py`, tag `v1.5.6`, create a GitHub
  release (the publish workflow checks the tag against the package version and runs the tests).
- Commit messages and releases carry no Claude co-author line.
