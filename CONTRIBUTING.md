There are many ways to contribute, you can find out all the ways on our
[Contribute](https://f-droid.org/contribute/) page. Find out how to get
involved, including as a translator, data analyst, tester, helping others, and
much more!

## Contributing Code

We want more contributors and want different points of view represented. Some
parts of the code make contributing quick and easy. Other parts make it
difficult and slow, so we ask that contributors have patience.

To submit a patch, please open a merge request on GitLab. If you are thinking of
making a large contribution, open an issue or merge request before starting
work, to get comments from the community. Someone may be already working on the
same thing, or there may be reasons why that feature isn't implemented. Once
there is agreement, then the work might need to proceed asynchronously with the
core team towards the solution.

To make it easier to review and accept your merge request, please follow these
guidelines:

* When at all possible, include tests. These can either be added to an existing
  test, or completely new. Practicing test-driven development will make it
  easiest to get merged. That usually means starting your work by writing tests.

* See [help-wanted](https://gitlab.com/fdroid/fdroidserver/-/issues/?sort=updated_desc&state=opened&label_name%5B%5D=help-wanted)
  tags for things that maintainers have marked as things they want to see
  merged.

* The amount of technical debt varies widely in this code base. There are some
  parts where the code is nicely isolated with good test coverage. There are
  other parts that are tangled and complicated, full of technical debt, and
  difficult to test.

* The general approach is to treat the tangled and complicated parts as an
  external API (albeit a bad one). That means it needs to stay unchanged as much
  as possible. Changes to those parts of the code will trigger a migration,
  which can require a lot of time and coordination. When there is time for large
  development efforts, we refactor the code to get rid of those areas of
  technical debt.

* We use [_black_](https://black.readthedocs.io/) code format, run `black .` to
  format the code. Whenever editing code in any file, the new code should be
  formatted as _black_. Some files are not yet fully in _black_ format (see
  _pyproject.toml_), our goal is to opportunistically convert the code whenever
  possible. As of the time of this writing, forcing the code format on all files
  would be too disruptive.  The officially supported _black_ version is the one
  in Debian/stable.

* Many of the tests run very fast and can be run interactively in isolation.
  Some of the essential test cases run slowly because they do things like
  signing files and generating signing keys.

* Some parts of the code are difficult to test, and currently require a
  relatively complete production setup in order to effectively test them. That
  is mostly the code around building packages, managing the disposable VM, and
  scheduling build jobs to run.

* For user visible changes (API changes, behaviour changes, etc.), consider
  adding a note in _CHANGELOG.md_. This could be a summarizing description of
  the change, and could explain the grander details. Have a look through
  existing entries for inspiration. Please note that this is NOT simply a copy
  of git-log one-liners. Also note that security fixes get an entry in
  _CHANGELOG.md_. This file helps users get more in-depth information of what
  comes with a specific release without having to sift through the higher noise
  ratio in git-log.
