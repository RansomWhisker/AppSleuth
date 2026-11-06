# AppSleuth

> A tool by [**rudranetra.com**](https://rudranetra.com) · more at [rudranetra.com/tools](https://rudranetra.com/tools)

One tool for mobile app security triage. Works on macOS, Linux and Windows (device pulls on Windows are experimental). Analyses **IPA**, **APK**, **APKS/XAPK** and **AAB**. Python standard library only.

| Command | What it does |
|---|---|
| `appsleuth scan app.ipa` | Static security scan (secrets, ATS / network config, exported components, weak crypto, hardening, hybrid web layer) |
| `appsleuth info app.apk` | One-screen summary: identity, signing, permissions, exported components, libraries, posture flags |
| `appsleuth diff old new` | Compare two builds: files by category, posture, findings, and a list of **regressions** |
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

## `appsleuth runtime` (experimental)

Observe what a running app really does, using Frida: root/jailbreak checks, plaintext HTTP actually requested, ciphers (ECB, DES), credentials written to SharedPreferences/NSUserDefaults, secrets in logs, debuggable WebViews.

    pip install "appsleuth[runtime]"          # adds Frida; frida-server must run on the device
    appsleuth runtime --android com.example.app --seconds 90
    appsleuth runtime --ios com.example.app --spawn

It is **observe-only** (no bypasses, nothing patched) and never stores values, only key names and descriptions. Use the app during the window: it can only report what it sees. **Status: new, and so far tested only on simulated events, not on a real device.** Treat results as leads.

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
