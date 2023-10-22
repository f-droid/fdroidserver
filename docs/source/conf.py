# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('../../fdroidserver'))

# -- Project information -----------------------------------------------------

project = 'fdroidserver'
copyright = '2021, The F-Droid Project'
author = 'The F-Droid Project'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'numpydoc',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    "sphinx.ext.intersphinx",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "pydata_sphinx_theme"

html_theme_options = {
    "gitlab_url": "https://gitlab.com/fdroid/fdroidserver",
    "show_prev_next": False,
    "navbar_end": ["search-field.html", "navbar-icon-links.html"],
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

html_sidebars = {
    "**": [],
}

#html_sidebars = {
#   '**': ['globaltoc.html', 'sourcelink.html', 'searchbox.html'],
#   'using/windows': ['windowssidebar.html', 'searchbox.html'],
#}

html_split_index = True
#numpydoc_validation_checks = {"all"}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
}
