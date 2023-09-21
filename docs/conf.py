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
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))
# -- Project information -----------------------------------------------------

project = "Testing Platform"
copyright = "LHC <info@nc3.lu>"
author = "Cédric Bonhomme <cedric@cedricbonhomme.org>"

# The full version, including alpha/beta/rc tags
release = "1.0.4"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    # "sphinx_autodoc_typehints",
    # "sphinx_multiversion",
    # "sphinxcontrib.mermaid",
    # "sphinxcontrib.bibtex",
    "sphinxcontrib.openapi",
]

# bibtex_bibfiles = ["refs.bib"]

# Patterns
# smv_tag_whitelist = r"^refs/tags/v\d+\.\d+\.\d+$|latest"
smv_released_pattern = r"^refs/tags/v\d+\.\d+\.\d+$"
# smv_branch_whitelist = r'main$'
smv_branch_whitelist = r"^(?!internationalization).*$"
smv_remote_whitelist = None

# mermaid_version = ""
# mermaid_cmd = "/home/cedric/git/pumpkin/docs/node_modules/@mermaid-js/mermaid-cli/src/cli.js"
# mermaid_output_format = "png"
# html_js_files = [
#     "js/mermaid.min.js",
# ]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_book_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_title = "Testing Platform"
html_theme_options = {
    "path_to_docs": "docs",
    "repository_url": "https://github.com/NC3-LU/TestingPlatform",
    # "repository_branch": "gh-pages",  # For testing
    "launch_buttons": {
        "binderhub_url": "https://github.com/NC3-LU/TestingPlatform",
    },
    "use_edit_page_button": True,
    "use_issues_button": True,
    "use_repository_button": True,
    "use_download_button": True,
    "home_page_in_toc": True,
    # For testing
    # "use_fullscreen_button": False,
    # "single_page": True,
    # "extra_footer": "<a href='https://google.com'>Test</a>",  # DEPRECATED KEY
    # "extra_navbar": "<a href='https://google.com'>Test</a>",
    # "show_navbar_depth": 2,
}
