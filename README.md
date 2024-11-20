<div align="center">

<p><img src="https://gitlab.com/fdroid/artwork/-/raw/master/fdroid-logo-2015/fdroid-logo.svg" width="200"></p>

# F-Droid Server
### Tools for maintaining an F-Droid repository system.

</div>

---

## What is F-Droid Server?

_fdroidserver_ is a suite of tools to publish and work with collections of
Android apps (APK files) and other kinds of packages.  It is used to maintain
the [f-droid.org application repository](https://f-droid.org/packages).  These
same tools can be used to create additional or alternative repositories for
publishing, or to assist in creating, testing and submitting metadata to the
f-droid.org repository, also known as
[_fdroiddata_](https://gitlab.com/fdroid/fdroiddata).

For documentation, please see <https://f-droid.org/docs>.

In the beginning, _fdroidserver_ was the complete server-side setup that ran
f-droid.org.  Since then, the website and other parts have been split out into
their own projects.  The name for this suite of tooling has stayed
_fdroidserver_ even though it no longer contains any proper server component.


## Installing

There are many ways to install _fdroidserver_, including using a range of
package managers.  All of the options are documented on the website:
https://f-droid.org/docs/Installing_the_Server_and_Repo_Tools


## Releases

The production setup of _fdroidserver_ for f-droid.org is run directly from the
_master_ branch.  This is put into production on an schedule (currently weekly).
So development and testing happens in the branches. We track branches using
merge requests.  Therefore, there are many WIP and long-lived merge requests.

There are also stable releases of _fdroidserver_.  This is mostly intended for
running custom repositories, where the build process is separate.  It can also
be useful as a simple way to get started contributing packages to _fdroiddata_,
since the stable releases are available in package managers.


## Tests

To run the full test suite:

    tests/run-tests

To run the tests for individual Python modules, see the `tests/test_*.py` files, e.g.:

    python -m unittest tests/test_metadata.py

It is also possible to run individual tests:

    python -m unittest tests.test_metadata.MetadataTest.test_rewrite_yaml_special_build_params

There is a growing test suite that has good coverage on a number of key parts of
this code base.  It does not yet cover all the code, and there are some parts
where the technical debt makes it difficult to write unit tests.  New tests
should be standard Python _unittest_ test cases.  Whenever possible, the old
tests written in _bash_ in _tests/run-tests_ should be ported to Python.

This test suite has built over time a bit haphazardly, so it is not as clean,
organized, or complete as it could be.  We welcome contributions.  The goal is
to move towards standard Python testing patterns and to expand the unit test
coverage.  Before rearchitecting any parts of it, be sure to [contact
us](https://f-droid.org/about) to discuss the changes beforehand.


### Additional tests for different linux distributions

These tests are also run on various configurations through GitLab CI. This is
only enabled for `master@fdroid/fdroidserver` because it takes longer to
complete than the regular CI tests.  Most of the time you won't need to worry
about them, but sometimes it might make sense to also run them for your merge
request. In that case you need to remove [these lines from .gitlab-ci.yml](https://gitlab.com/fdroid/fdroidserver/-/blob/0124b9dde99f9cab19c034cbc7d8cc6005a99b48/.gitlab-ci.yml#L90-91)
and push this to a new branch of your fork.

Alternatively [run them
locally](https://docs.gitlab.com/runner/commands/README.html#gitlab-runner-exec)
like this: `gitlab-runner exec docker ubuntu_lts`


## Documentation

The API documentation based on the docstrings gets automatically
published [here](https://fdroid.gitlab.io/fdroidserver) on every commit
on the `master` branch.

It can be built locally via

```bash
pip install -e .[docs]
cd docs
sphinx-apidoc -o ./source ../fdroidserver -M -e
sphinx-autogen -o generated source/*.rst
make html
```

To additionally lint the code call
```bash
pydocstyle fdroidserver --count
```

When writing docstrings you should follow the
[numpy style guide](https://numpydoc.readthedocs.io/en/latest/format.html).


## Translation

Everything can be translated.  See
[Translation and Localization](https://f-droid.org/docs/Translation_and_Localization)
for more info.

<div align="center">

[![](https://hosted.weblate.org/widgets/f-droid/-/287x66-white.png)](https://hosted.weblate.org/engage/f-droid)

<details>
<summary>View translation status for all languages.</summary>

[![](https://hosted.weblate.org/widgets/f-droid/-/fdroidserver/multi-auto.svg)](https://hosted.weblate.org/engage/f-droid/?utm_source=widget)

</details>

</div>
