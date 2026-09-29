# Rick's SideStore source

Automatically tracks the latest stable [YTKACE release](https://github.com/itzzace/ytkace/releases/latest), selecting the modern iOS IPA, and [EeveeSpotify release](https://github.com/estrogencat/EeveeIPA/releases/latest), selecting the regular Liquid Glass IPA. Downloads link directly to upstream GitHub assets. This repository never rehosts, modifies, decrypts, or signs an IPA.

## Add the source

In SideStore, open **Sources → +** (under Browse in some versions), then paste:

```text
https://raw.githubusercontent.com/rickhcchan/sidestore-source/main/apps.json
```

The same URL works as an AltStore Classic source. The repository must remain public; GitHub Pages is unnecessary. Keep this URL and the configured source identifier stable. App identities are their real IPA bundle identifiers: `com.google.ios.youtube` for YTKACE and `com.spotify.client` for EeveeSpotify. They are not separate identities from other variants of those apps.

**SideStore does not manage apps installed inside LiveContainer.** Adding this source does not update those guest apps: download the upstream IPA and import/update it through LiveContainer. Its [documentation explains the guest-app model](https://github.com/LiveContainer/LiveContainer#readme).

## Automatic and manual updates

In GitHub **Actions**, enable workflows if prompted. **Update source** runs every six hours at 00:23, 06:23, 12:23 and 18:23 UTC. Select **Run workflow → main** for an immediate check. Only the built-in `GITHUB_TOKEN` is needed; no secrets, Apple account, signing certificate, or external service.

The update job requests `contents: write`; tests only request read access. Repository/organisation policy and branch protection must allow the bot to push to `main`. On a permission error, check **Settings → Actions → General → Workflow permissions** and branch rules. Runs are serialized, failures leave the published catalogue intact, and identical results create no commit. A concurrent human push causes a normal push rejection, never a force-push; rerun on the new head.

[GitHub schedules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule) run on the default branch, can be delayed or dropped, and are disabled in public repositories after **60 days without repository activity**. No-change checks produce no activity commit. Re-enable a disabled workflow from Actions and run it manually; check periodically rather than relying on a guaranteed six-hour delivery time.

Locally, use Python **3.10+** (CI uses 3.12), with no third-party packages:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/update.py
python3 scripts/update.py --validate
```

An optional `GITHUB_TOKEN` environment variable increases API rate limits. Without it, public API access works subject to GitHub's unauthenticated limits. The IPA is downloaded to a temporary directory and deleted after inspection. Allow enough disk/memory for the app; files over 2 GiB fail explicitly.

## Selection and catalogue behavior

The updater uses GitHub's `/releases/latest` endpoint and checks draft/prerelease flags. It fetches every asset page. Observed v1.1.1 assets include `YTKACE_1.1.1_YouTube_21.39.4.ipa`, the separate `YouTube_iOS16_21.33.6.ipa`, and two `.deb` packages. Configuration requires exactly one modern-name match, excludes legacy/iOS16, and accepts only `.ipa`. Missing, renamed, or ambiguous assets fail; it never silently falls back to an older release.

For EeveeSpotify, the initial release is `6.6.8-LG-2026-09-23-00-00-00` (Spotify 9.1.84). Selection requires `EeveeSpotify-<app version>-ESR-<tweak version>-LG.ipa` and excludes `-patched.ipa`. The [maintainer's installation notes](https://github.com/estrogencat/EeveeIPA#installation) support the regular variant with SideStore; the patched variant requires certificate-based signing tools or TrollStore. This source follows future latest stable releases with the same regular Liquid Glass naming, rather than pinning the initial tag. If a future latest release lacks that variant, the sync fails and keeps the existing catalogue. Its icon uses a commit-pinned upstream EeveeSpotify PNG because this IPA has no web-compatible declared primary icon.

The main `Payload/*.app/Info.plist` supplies bundle ID, version, build and minimum iOS. The download size and upstream SHA-256 (when available) are checked. The catalogue includes the computed SHA-256, upstream publication date and notes, the declared primary icon, and permissions read from the main app and extensions. Unsupported executable/DER-only entitlement formats fail explicitly. All projects must pass before the catalogue is atomically replaced.

The shared format uses `apps[].versions`, `buildVersion`, `minOSVersion`, `appPermissions`, and `news`, following [AltStore's source documentation](https://faq.altstore.io/developers/make-a-source) and SideStore's [Source](https://sidestore.io/sidestore-source-types/interfaces/Source.html), [App](https://sidestore.io/sidestore-source-types/interfaces/App.html) and [Version](https://sidestore.io/sidestore-source-types/interfaces/Version.html) documentation. It publishes only the current release, with no historical/iOS16 fallback. Icons are copied from the original IPA into content-addressed PNG files; the IPA itself is never published here.

## Update detection and troubleshooting

The YTKACE and EeveeSpotify tags describe their tweaks, not necessarily the apps' internal versions. Never replace IPA version/build values with the tag or a timestamp.

[AltStore detects differing app versions/builds, not release dates](https://faq.altstore.io/developers/updating-apps). [SideStore 0.6.4's `hasUpdate`](https://github.com/SideStore/SideStore/blob/0.6.4/AltStore/Core/Model/InstalledApp.swift) compares semantic app versions for normal numeric versions; a separate build-only change does **not** trigger that path. It falls back to version/build matching for unparseable versions. Newer client behavior can differ.

If a tweak-only release keeps both version and build unchanged, the updater replaces the current download/notes and emits a stable release-specific **news** item with `notify: true`. News notification delivery depends on client settings/background checks; it is not an app-update badge. Duplicate version/build entries and invented versions are never emitted.

If no update appears, refresh the source, check Actions and upstream release notes, then compare the installed app version with `apps.json`. Ensure your iOS meets `minOSVersion`. For a same-version tweak update, manually download the linked latest IPA and install it over the existing app through SideStore using the same identity/account; a normal signing refresh alone does not fetch a new release. Back up important app data before reinstalling; deleting the app is not required by this updater. For LiveContainer guests, use LiveContainer instead.

## Add another GitHub project

Add an entry to `config.json`'s `projects` array with a unique `id`, `repository` (`owner/repo`), display fields, actual `bundleIdentifier`, and an `assetPattern` regular expression matched against the **entire** asset name. Inspect its real releases before choosing the pattern; `excludePattern` is optional. Configure `iconURL` if the IPA has no ordinary PNG primary icon. Two projects cannot share a bundle ID. No updater changes are needed for compatible IPA formats.

Run tests and a real sync, review `apps.json` and any new `icons/`, then commit the configuration and outputs. Bundle-ID changes stop the updater for review rather than silently replacing an existing app identity.

## Verification scope

Automated tests cover asset ambiguity/exclusion, XML and binary plists, main-app selection, entitlement parsing, exact catalogue values, tweak-only releases, multiple projects, download integrity, no-change runs, and failure preservation. Real upstream sync and JSON validation are performed before publication. This does **not** establish successful signing or installation on an iPhone; those have not been tested.
