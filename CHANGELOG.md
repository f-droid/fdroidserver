# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## unreleased

### Added

### Fixed

### Removed

## [2.3.2] - 2024-11-26

### Fixed

* install: fix downloading from GitHub Releases and Maven Central.
* Sync translations for: ca fa fr pt ru sr ta zh_Hant

## [2.3.1] - 2024-11-25

### Fixed

* Sync all translations for: cs de es fr ga pt_BR ru sq zh_Hans.
* Drop use of deprecated imghdr library to support Python 3.13.
* Install biplist and pycountry by default on macOS.
* Fixed running test suite out of dist tarball.

## [2.3.0] - 2024-11-21

### Added

* YAML 1.2 as native format for all _.yml_ files, including metadata and config.
* install: will now fetch _F-Droid.apk_ and install it via `adb`.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1546
* scanner: scan APK Signing Block for known block types like Google Play
  Signature aka "Frosting".
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1555
* Support Rclone for deploying to many different cloud services.
* deploy: support deploying to GitHub Releases.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1471
* scanner: support libs.versions.toml
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1526
* Consider subdir for triple-t metadata discovery in Flutter apps.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1541
* deploy: added `index_only:` mode for mirroring the index to small hosting
  locations. https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1420
* Support publishing repos in AltStore format.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1465
* Support indexing iOS IPA app files.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1413
* deploy: _config/mirrors.yml_ file with support for adding per-mirror metadata,
  like `countryCode:`.
* Repo's categories are now set in the config files.
* lint: check syntax of config files.
* publish: ``--error-on-failed` to exit when signing/verifying fails.
* scanner: `--refresh` and `refresh_config:` to control triggering a refresh of
  the rule sets.
* Terminal output colorization and `--color` argument to control it.
* New languages: Catalan (ca), Irish (ga), Japanese (ja), Serbian (sr), and
  Swahili (sw).
* Support donation links from `community_bridge`, `buy_me_a_coffee`.

### Fixed

* Use last modified time and file size for caching data about scanned APKs
  instead of SHA-256 checksum.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1542
* `repo_web_base_url:` config for generating per-app URLs for viewing in
  browsers.  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1178
* `fdroid scanner` flags WebAssembly binary _.wasm_ files.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1562
* Test suite as standard Python `unittest` setup (thanks @ghost.adh).
* scanner: error on dependency files without lock file.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1504
* nightly: finding APKs in the wrong directory. (thanks @WrenIX)
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1512
* `AllowedAPKSigningKeys` works with all single-signer APK signatures.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1466
* Sync all translations for: cs de it ko pl pt pt_BR pt_PT ro ru sq tr uk
  zh_Hans zh_Hant.
* Support Androguard 4.x.
* Support Python 3.12.

### Removed

* Drop all uses of _stats/known_apks.txt_ and the `update_stats:` config key.
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1547
* The `maven:` field is now always a string, with `yes` as a legacy special
  value.  It is no longer treated like a boolean in any case.
* scanner: jcenter is no longer an allowed Maven repo.
* build: `--reset-server` removed (thanks @gotmi1k).

## [2.2.2] - 2024-04-24

### Added

* Include sdkmanager as dep in setup.py for Homebrew package.
  https://github.com/Homebrew/homebrew-core/pull/164510

## [2.2.1] - 2023-03-09

### Added

* `download_repo_index_v2()` and `download_repo_index_v2()` API functions
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1323

### Fixed

* Fix OpenJDK detection on different CPU architectures
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1315

### Removed

* Purge all references to `zipalign`, that is delegated to other things
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1316
* Remove obsolete, unused `buildozer` build type
  https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1322

## [2.2.0] - 2023-02-20

### Added
* Support index-v2 format, localizable Anti-Features, Categories
* New entry point for repos, entry.jar, signed with modern algorithms
* New config/ subdirectory for localizable configuration
* Script entries in metadata files (init, prebuild, build, etc) now handled as
  lists so they now support using && or ; in the script, and behave like
  .gitlab-ci.yml and other CI YAML.
* GPG signatures for index-v1.json and index-v2.json
* Use default.txt as fallback changelog when inserting fastlane metadata
* scanner: F-Droid signatures now maintained in fdroid/suss
* scanner: maintain signature sources in config.yml, including Exodus Privacy
* scanner: use dexdump for class names
* scanner: directly scan APK files when given a path
* scanner: recursively scan APKs for DEX and ZIP using file magic
* signindex: validate index files before signing
* update: set ArchivePolicy based on VercodeOperation/signature
* Include IPFS CIDv1 in index-v2.json for hosting repos on IPFS
* Per-repo beta channel configuration
* Add Czech translation

### Fixed

* apksigner v30 or higher now required for verifying and signing APKs
* 3.9 as minimum supported Python version
* Lots of translation updates
* Better pip packaging
* nightly: big overhaul for reliable operation on all Debian/Ubuntu versions
* Improved logging, fewer confusing verbose messages
* scanner: fix detection of binary files without extension
* import: more reliable operation, including Flutter apps
* Support Java 20 and up

### Removed
* Remove obsolete `fdroid stats` command

## [2.1.1] - 2022-09-06

* gradlew-fdroid: Include latest versions and checksums
* nightly: update Raw URLs to fix breakage and avoid redirects
* signindex: gpg-sign index-v1.json and deploy it
* update: fix --use-date-from-apk when used with files (#1012)

## [2.1] - 2022-02-22

For a more complete overview, see the [2.1
milestone](https://gitlab.com/fdroid/fdroidserver/-/milestones/11)

## [2.0.5] - 2022-09-06

### Fixed

* gradlew-fdroid: Include latest versions and checksums
* nightly: add support for GitHub Actions
* nightly: update Raw URLs to fix breakage and avoid redirects
* update: fix --use-date-from-apk when used with files (#1012)
* Fix GitLab CI

## [2.0.4] - 2022-06-29

### Fixed

* deploy: ensure progress is instantiated before trying to use it
* signindex: gpg-sign index-v1.json and deploy it
  [1080](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1080)
  [1124](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1124)

## [2.0.3] - 2021-07-01

### Fixed

* Support AutoUpdateMode: Version without pattern
  [931](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/931)

## [2.0.2] - 2021-06-01

### Fixed

* fix "ruamel round_trip_dump will be removed"
  [932](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/932)

## [2.0.1] - 2021-03-09

### Fixed

* metadata: stop setting up source repo when running lint/rewritemeta
* scanner: show error if scan_binary fails to run apkanalyzer
* common: properly parse version from NDK's source.properties
* update: stop extracting and storing XML icons, they're useless
* index: raise error rather than crash on bad repo file
* update: handle large, corrupt, or inaccessible fastlane/triple-t files
* Update SPDX License List
* checkupdates: set User-Agent to make gitlab.com happy
* Run push_binary_transparency only once

## [2.0] - 2021-01-31

For a more complete overview, see the [2.0
milestone](https://gitlab.com/fdroid/fdroidserver/-/milestones/10)

### Added
* `fdroid update` inserts donation links based on upstream's _FUNDING.yml_
  ([!754](https://gitlab.com/fdroid/fdroidserver/merge_requests/754))
* Stable, public API for most useful functions
  ([!798](https://gitlab.com/fdroid/fdroidserver/merge_requests/798))
* Load with any YAML lib and use with the API, no more custom parser needed
  ([!826](https://gitlab.com/fdroid/fdroidserver/merge_requests/826))
  ([!838](https://gitlab.com/fdroid/fdroidserver/merge_requests/838))
* _config.yml_ for a safe, easy, standard configuration format
  ([!663](https://gitlab.com/fdroid/fdroidserver/merge_requests/663))
* Config options can be set from environment variables using this syntax:
  `keystorepass: {env: keystorepass}`
  ([!669](https://gitlab.com/fdroid/fdroidserver/merge_requests/669))
* Add SHA256 to filename of repo graphics
  ([!669](https://gitlab.com/fdroid/fdroidserver/merge_requests/669))
* Support for srclibs metadata in YAML format
  ([!700](https://gitlab.com/fdroid/fdroidserver/merge_requests/700))
* Check srclibs and app-metadata files with yamllint
  ([!721](https://gitlab.com/fdroid/fdroidserver/merge_requests/721))
* Added plugin system for adding subcommands to `fdroid`
  ([!709](https://gitlab.com/fdroid/fdroidserver/merge_requests/709))
* `fdroid update`, `fdroid publish`, and `fdroid signindex` now work
  with SmartCard HSMs, specifically the NitroKey HSM
  ([!779](https://gitlab.com/fdroid/fdroidserver/merge_requests/779))
  ([!782](https://gitlab.com/fdroid/fdroidserver/merge_requests/782))
* `fdroid update` support for Triple-T Gradle Play Publisher v2.x
  ([!683](https://gitlab.com/fdroid/fdroidserver/merge_requests/683))
* Translated into: bo de es fr hu it ko nb_NO pl pt pt_BR pt_PT ru sq tr uk
  zh_Hans zh_Hant

### Fixed
* Smoother process for signing APKs with `apksigner`
  ([!736](https://gitlab.com/fdroid/fdroidserver/merge_requests/736))
  ([!821](https://gitlab.com/fdroid/fdroidserver/merge_requests/821))
* `apksigner` is used by default on new repos
* All parts except _build_ and _publish_ work without the Android SDK
  ([!821](https://gitlab.com/fdroid/fdroidserver/merge_requests/821))
* Description: is now passed to clients unchanged, no HTML conversion
  ([!828](https://gitlab.com/fdroid/fdroidserver/merge_requests/828))
* Lots of improvements for scanning for proprietary code and trackers
  ([!748](https://gitlab.com/fdroid/fdroidserver/merge_requests/748))
  ([!REPLACE](https://gitlab.com/fdroid/fdroidserver/merge_requests/REPLACE))
  ([!844](https://gitlab.com/fdroid/fdroidserver/merge_requests/844))
* `fdroid mirror` now generates complete, working local mirror repos
* fix build-logs dissapearing when deploying
  ([!685](https://gitlab.com/fdroid/fdroidserver/merge_requests/685))
* do not crash when system encoding can not be retrieved
  ([!671](https://gitlab.com/fdroid/fdroidserver/merge_requests/671))
* checkupdates: UpdateCheckIngore gets properly observed now
  ([!659](https://gitlab.com/fdroid/fdroidserver/merge_requests/659),
  [!660](https://gitlab.com/fdroid/fdroidserver/merge_requests/660))
* keep yaml metadata when rewrite failed
  ([!658](https://gitlab.com/fdroid/fdroidserver/merge_requests/658))
* import: `template.yml` now supports omitting values
  ([!657](https://gitlab.com/fdroid/fdroidserver/merge_requests/657))
* build: deploying buildlogs with rsync
  ([!651](https://gitlab.com/fdroid/fdroidserver/merge_requests/651))
* `fdroid init` generates PKCS12 keystores, drop Java < 8 support
  ([!801](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/801))
* Parse Version Codes specified in hex
  ([!692](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/692))
* Major refactoring on core parts of code to be more Pythonic
  ([!756](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/756))
* `fdroid init` now works when installed with pip

### Removed
* Removed all support for _.txt_ and _.json_ metadata
  ([!772](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/772))
* dropped support for Debian 8 _jessie_ and 9 _stretch_
* dropped support for Ubuntu releases older than bionic 18.04
* dropped `fdroid server update` and `fdroid server init`,
  use `fdroid deploy`
* `fdroid dscanner` was removed.
  ([!711](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/711))
* `make_current_version_link` is now off by default
* Dropped `force_build_tools` config option
  ([!797](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/797))
* Dropped `accepted_formats` config option, there is only _.yml_ now
  ([!818](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/818))
* `Provides:` was removed as a metadata field
  ([!654](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/654))
* Remove unused `latestapps.dat`
  ([!794](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/794))


## [1.1.4] - 2019-08-15
### Fixed
* include bitcoin validation regex required by fdroiddata
* merged Debian patches to fix test suite there

## [1.1.3] - 2019-07-03
### Fixed
* fixed test suite when run from source tarball
* fixed test runs in Debian

## [1.1.2] - 2019-03-29
### Fixed
* fix bug while downloading repo index
  ([!636](https://gitlab.com/fdroid/fdroidserver/merge_requests/636))

## [1.1.1] - 2019-02-03
### Fixed
* support APK Signature v2 and v3
* all SDK Version values are output as integers in the index JSON
* take graphics from Fastlane dirs using any valid RFC5646 locale
* print warning if not running in UTF-8 encoding
* fdroid build: hide --on-server cli flag

## [1.1] - 2019-01-28
### Fixed
* a huge update with many fixes and new features:
  https://gitlab.com/fdroid/fdroidserver/milestones/7
* can run without and Android SDK installed
* much more reliable operation with large binary APK collections
* sync all translations, including newly added languages: hu it ko pl pt_PT ru
* many security fixes, based on the security audit
* NoSourceSince automatically adds SourceGone Anti-Feature
* aapt scraping works with all known aapt versions
* smoother mirror setups
* much faster `fdroid update` when using androguard

[Unreleased]: https://gitlab.com/fdroid/fdroidserver/compare/1.1.4...master
[1.1.4]: https://gitlab.com/fdroid/fdroidserver/compare/1.1.3...1.1.4
[1.1.3]: https://gitlab.com/fdroid/fdroidserver/compare/1.1.2...1.1.3
[1.1.2]: https://gitlab.com/fdroid/fdroidserver/compare/1.1.1...1.1.2
[1.1.1]: https://gitlab.com/fdroid/fdroidserver/compare/1.1...1.1.1
[1.1]: https://gitlab.com/fdroid/fdroidserver/tags/1.1
