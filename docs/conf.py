# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "cle"
project_copyright = f"{datetime.datetime.now().year}, The angr Project contributors"
author = "The angr Project"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.coverage",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for autodoc -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#configuration
autoclass_content = "class"
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "show-inheritance": True,
    "special-members": "__init__",
    "undoc-members": True,
}
autodoc_class_signature = "separated"
autodoc_inherit_docstrings = True
autodoc_typehints = "both"
typehints_use_signature = True
typehints_use_signature_return = True

# -- Options for coverage ----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/coverage.html
coverage_write_headline = False

coverage_ignore_pyobjects = [
    "cle.address_translator.AT",  # Alias to AddressTranslator
]

# -- Options for intersphinx -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "archinfo": ("https://docs.angr.io/projects/archinfo/en/latest/", None),
    "pyvex": ("https://docs.angr.io/projects/pyvex/en/latest/", None),
}


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]
