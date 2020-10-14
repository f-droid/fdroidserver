# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]
### Added
* makebuildserver: added ndk r20
  ([!663](https://gitlab.com/fdroid/fdroidserver/merge_requests/663))
* added support for gradle 5.5.1
  ([!656](https://gitlab.com/fdroid/fdroidserver/merge_requests/656))
* add SHA256 to filename of repo graphics
  ([!669](https://gitlab.com/fdroid/fdroidserver/merge_requests/669))
* support for srclibs metadata in YAML format
  ([!700](https://gitlab.com/fdroid/fdroidserver/merge_requests/700))
* check srclibs and app-metadata files with yamllint
  ([!721](https://gitlab.com/fdroid/fdroidserver/merge_requests/721))

### Fixed
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

### Removed
* removed support for txt and json metadata
  ([!772](https://gitlab.com/fdroid/fdroidserver/-/merge_requests/772))
* `make_current_version_link` is now off by default

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
