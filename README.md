# AppSleuth

> A tool by [**rudranetra.com**](https://rudranetra.com) · more at [rudranetra.com/tools](https://rudranetra.com/tools)

One tool for mobile app security triage. Works on macOS, Linux and Windows (device pulls on Windows are experimental). Analyses **IPA**, **APK**, **APKS/XAPK** and **AAB**. Python standard library only.

| Command | What it does |
|---|---|
| `appsleuth scan app.ipa` | Static security scan (secrets, ATS / network config, exported components, weak crypto, hardening, hybrid web layer) |
| `appsleuth info app.apk` | One-screen summary: identity, signing, permissions, exported components, libraries, posture flags |
| `appsleuth diff old new` | Compare two builds: files by category, posture, findings, and a list of **regressions** |
| `appsleuth sbom app.apk [--cves]` | Inventory embedded libraries, write a **CycloneDX SBOM**, and optionally look them up on [OSV.dev](https://osv.dev) for known CVEs |
| `appsleuth endpoints app.ipa` | Every host and API path the app references, labelled first-party / known SDK / other, with raw-IP, cleartext, tunnel and staging flags |
| `appsleuth links app.apk [--check-network]` | Deep links, custom URL schemes, App Links / Universal Links, exposed handlers; optionally verifies `assetlinks.json` / `apple-app-site-association` |
| `appsleuth cloud app.apk [--check]` | Firebase / S3 / GCS / Azure backends the app uses; opt-in read-only test of whether they are open to anonymous access |
| `appsleuth data` | Pull an app's data container from a jailbroken iPhone (SSH) or an Android device (adb) and audit it, or audit a directory you already pulled |

`appsleuth <file>` is shorthand for `scan`.

## Install

    pipx install appsleuth   # recommended
    pip install .          # or, from a clone: gives you the `appsleuth` command
    python3 -m appsleuth …   # or run in place

## Examples

    appsleuth scan app.ipa --fail-on HIGH
    appsleuth info RSWealth.apks --full
    appsleuth diff v1.apk v2.apk --fail-on-regression
    appsleuth data --ios --host 9 -b com.example.app
    appsleuth data --android -p com.example.app --method auto
    appsleuth data --audit-dir ./pulled --platform android

Reports (`report.json/md/html`) are written to `-o DIR`.

**Encrypted IPAs:** if the main binary (or a framework) is still FairPlay-encrypted, AppSleuth cannot see its code, so it prints a warning and puts it at the top of every report. A clean result on such a file does not mean the app is secure; re-dump it decrypted and scan again.

## Intel commands: network use and consent

`sbom`, `endpoints`, `links` and `cloud` run **offline by default**. Anything that touches the network is opt-in:

* `sbom --cves` sends only library names and versions to OSV.dev (results cached 24 h in `~/.cache/appsleuth`; `--offline` uses the cache only).
* `links --check-network` downloads the public `assetlinks.json` / `apple-app-site-association` files of the domains the app claims.
* `cloud --check` sends **read-only, unauthenticated** requests to the app's Firebase / S3 / GCS backends and records only the HTTP result, never any returned data. Targets are restricted to a fixed allow-list of cloud hostnames and must resolve to public addresses. **Only use it on apps you are authorised to test.**

`appsleuth diff` also lists new and removed network hosts between builds (a new cleartext, raw-IP or staging host is flagged).

    appsleuth sbom app.apk --cves        # also writes sbom.cdx.json
    appsleuth endpoints app.ipa
    appsleuth links app.apk --check-network
    appsleuth cloud app.apk              # discover only
    appsleuth cloud app.apk --check      # authorised targets only

## `appsleuth runtime` (experimental)

Observe what a running app really does, using Frida: root/jailbreak checks, plaintext HTTP actually requested, ciphers (ECB, DES), credentials written to SharedPreferences/NSUserDefaults, secrets in logs, debuggable WebViews.

    pip install "appsleuth[runtime]"          # adds Frida; frida-server must run on the device
    # (agent sources: appsleuth/runtime_js/agents; rebuild with `npm install && npm run build` there)
    appsleuth runtime --android com.example.app --seconds 90
    appsleuth runtime --ios com.example.app --spawn

It is **observe-only** (no bypasses, nothing patched) and never stores values, only key names and descriptions. Use the app during the window: it can only report what it sees. **Status:** tested on a real jailbroken iPhone (Dopamine, Frida 17) and a rooted Pixel 6a (Android 16, Frida 17.15). On Android, `--spawn` falls back to a delayed attach if an app crashes under early instrumentation, and attaching to a running app finds it by package name. The `pip` Frida version must match the `frida-server` on the phone. Only calls made while the probe runs are visible, and results are leads, not proof. Probes count only calls from the app's own code, not from the jailbreak's tweak loader.

## Keeping false positives low

* **At detection**: placeholder and sample secrets dropped; public client identifiers (Google API keys, OAuth client IDs, Razorpay key IDs) reported as INFO; JWTs must decode; PEM needs a real body; whole-word crypto matching; digests, UUIDs and identifiers filtered from the entropy scan; documentation/schema URLs ignored; launcher activities not "exported"; Swift binaries not flagged for stack canaries.
* **Corroboration** (`triage`): cleartext URLs are demoted when ATS or the Android target SDK already blocks cleartext; config-split APKs don't repeat base-manifest findings.
* **Yours**: `--ignore-file` (default `.appsleuth-ignore`) with `title:`, `location:`, `evidence:`, `fingerprint:`, `severity:` rules and ` -- reason`. `--min-severity`, `--min-confidence`.
* Nothing is silently lost: `report.json` has a `triage` section listing everything demoted, dropped, ignored or hidden. `--no-triage` shows raw output.

Findings are leads for manual review, not confirmed vulnerabilities; each carries a `confidence`.

## `appsleuth data` safety

Values are **redacted by default** (`--show-values` shows a short preview, never the full secret). Pulled archives are extracted defensively (regular files only, no links, no traversal, size/count caps); SQLite is opened read-only with an authorizer; XML with a DOCTYPE is refused; host/user/package inputs are validated and shell-quoted. Only use it on devices and apps you are authorised to test.

## Tests

    python3 -m unittest discover -s tests -t .

## Licence

[MIT](LICENSE) © Rudranetra India Private Limited — [rudranetra.com](https://rudranetra.com)
