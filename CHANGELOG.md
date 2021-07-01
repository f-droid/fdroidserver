# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]


## [2.0.3] - 2021-07-01

### Fixed

* Support AutoUpdateMode: Version without pattern
  [931](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/931)

## [2.0.2] - 2021-06-01

### Fixed

* fix "ruamel round_trip_dump will be removed"

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
