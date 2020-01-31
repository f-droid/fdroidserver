<a name="build-status"></a>

| CI Builds                |  fdroidserver | buildserver | fdroid build --all | publishing tools |
|--------------------------|:-------------:|:-----------:|:------------------:|:----------------:|
| GNU/Linux                | [![fdroidserver status on GNU/Linux](https://gitlab.com/fdroid/fdroidserver/badges/master/build.svg)](https://gitlab.com/fdroid/fdroidserver/builds) | [![buildserver status](https://jenkins.debian.net/job/reproducible_setup_fdroid_build_environment/badge/icon)](https://jenkins.debian.net/job/reproducible_setup_fdroid_build_environment) | [![fdroid build all status](https://jenkins.debian.net/job/reproducible_fdroid_build_apps/badge/icon)](https://jenkins.debian.net/job/reproducible_fdroid_build_apps/) | [![fdroid test status](https://jenkins.debian.net/job/reproducible_fdroid_test/badge/icon)](https://jenkins.debian.net/job/reproducible_fdroid_test/) |
| macOS                    | [![fdroidserver status on macOS](https://travis-ci.org/f-droid/fdroidserver.svg?branch=master)](https://travis-ci.org/f-droid/fdroidserver) | | | |


# F-Droid Server

Server for [F-Droid](https://f-droid.org), the Free Software repository system
for Android.

The F-Droid server tools provide various scripts and tools that are
used to maintain the main
[F-Droid application repository](https://f-droid.org/packages).  You
can use these same tools to create your own additional or alternative
repository for publishing, or to assist in creating, testing and
submitting metadata to the main repository.

For documentation, please see <https://f-droid.org/docs/>, or you can
find the source for the documentation in
[fdroid/fdroid-website](https://gitlab.com/fdroid/fdroid-website).


### What is F-Droid?

F-Droid is an installable catalogue of FOSS (Free and Open Source Software)
applications for the Android platform. The client makes it easy to browse,
install, and keep track of updates on your device.


### Installing

There are many ways to install _fdroidserver_, they are documented on
the website:
https://f-droid.org/docs/Installing_the_Server_and_Repo_Tools

All sorts of other documentation lives there as well.


### Tests

There are many components to all of the tests for the components in
this git repo.  The most commonly used parts of well tested, while
some parts still lack tests.  This test suite has built over time a
bit haphazardly, so it is not as clean, organized, or complete as it
could be.  We welcome contributions.  Before rearchitecting any parts
of it, be sure to [contact us](https://f-droid.org/about) to discuss
the changes beforehand.


#### `fdroid` commands

The test suite for all of the `fdroid` commands is in the _tests/_
subdir.  _.gitlab-ci.yml_ and _.travis.yml_ run this test suite on
various configurations.

* _tests/complete-ci-tests_ runs _pylint_ and all tests on two
  different pyvenvs
* _tests/run-tests_ runs the whole test suite
* _tests/*.TestCase_ are individual unit tests for all of the `fdroid`
  commands, which can be run separately, e.g. `./update.TestCase`.


#### Additional tests for different linux distributions

These tests are also run on various distributions through GitLab CI. This is
only enabled for `master@fdroid/fdroidserver` because it'll take longer to
complete than the regular CI tests.  Most of the time you won't need to worry
about them but sometimes it might make sense to also run them for your merge
request. In that case you need to remove [these lines from
.gitlab-ci.yml](https://gitlab.com/fdroid/fdroidserver/blob/master/.gitlab-ci.yml#L34-35)
and push this to a new branch of your fork.

Alternatively [run them
locally](https://docs.gitlab.com/runner/commands/README.html#gitlab-runner-exec)
like this: `gitlab-runner exec docker ubuntu_lts`

#### buildserver

The tests for the whole build server setup are entirely separate
because they require at least 200GB of disk space, and 8GB of
RAM. These test scripts are in the root of the project, all starting
with _jenkins-_ since they are run on https://jenkins.debian.net.


## Translation

Everything can be translated.  See
[Translation and Localization](https://f-droid.org/docs/Translation_and_Localization)
for more info.
[![translation status](https://hosted.weblate.org/widgets/f-droid/-/fdroidserver/multi-auto.svg)](https://hosted.weblate.org/engage/f-droid/?utm_source=widget)
