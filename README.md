# AppSleuth

> A tool by [**rudranetra.com**](https://rudranetra.com) · more at [rudranetra.com/tools](https://rudranetra.com/tools)

One tool for mobile app security triage. Works on **IPA**, **APK**, **APKS/XAPK** and **AAB**. Python standard library only.

| Command | What it does |
|---|---|
| `appsleuth scan app.ipa` | Static security scan (secrets, ATS / network config, exported components, weak crypto, hardening, hybrid web layer) |
| `appsleuth info app.apk` | One-screen summary: identity, signing, permissions, exported components, libraries, posture flags |
| `appsleuth diff old new` | Compare two builds: files by category, posture, findings, and a list of **regressions** |
| `appsleuth data` | Pull an app's data container from a jailbroken iPhone (SSH) or an Android device (adb) and audit it, or audit a directory you already pulled |

`appsleuth <file>` is shorthand for `scan`.

## Install

    pipx install git+https://github.com/RansomWhisker/AppSleuth   # recommended
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
