# Sphinx configuration for the champsim_tracer documentation.
#
# Build:
#     pip install sphinx furo
#     make -C contrib/plugins/champsim_tracer/docs html
#
# Output lands in contrib/plugins/champsim_tracer/docs/_build/html.

import os
import sys

# Pull our local Sphinx extensions onto sys.path.
sys.path.insert(0, os.path.abspath("_ext"))

project = "ChampSim Tracer"
author = "Maccoy Merrell"
# Copyright assigned to the ChampSim team — the plugin's intended
# downstream consumer.  Author is the individual contributor.
copyright = "2026, ChampSim"

# Read the trace format version from the C header so the docs and the
# wire format never drift.  The format spec page references this.
import re

def _read_format_version() -> str:
    header = os.path.join(os.path.dirname(__file__), "..", "champsim_tracer.h")
    try:
        with open(header, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"#define\s+CST_MAGIC\s+0x([0-9a-fA-F]+)u", line)
                if m:
                    magic = int(m.group(1), 16)
                    # Magic byte is "CST" + version-byte; the version
                    # byte is the high byte (e.g., 0x19 → "1.9").
                    vb = (magic >> 24) & 0xFF
                    return f"{vb >> 4}.{vb & 0xF}"
    except FileNotFoundError:
        pass
    return "unknown"

release = _read_format_version()
version = release

extensions = [
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.intersphinx",
    # myst-parser lets format.md stay as the canonical wire-format
    # spec while Sphinx renders it alongside the .rst pages.  Optional
    # — the format page falls back to a stub if myst isn't installed.
    "myst_parser",
    # Local extension that parses the per-ISA classification tables
    # in champsim_tracer_mnemonics_*.h and emits the appendix at
    # _generated/encoding_tables.rst before sources are read.
    "encoding_tables",
    # Local extension that walks every parsed doctree and adds index
    # entries for well-known symbol names (GEN_OP_*, REG_*, BRANCH_*,
    # CST_FID_*, SYNC_*, BODY_TAG_*, validator subcommands, ...).
    # Keeps the genindex page populous without hand-curating
    # `.. index::` directives across every section.
    "auto_index",
]

# Treat both .rst and .md as primary docs.  format.md is markdown so
# the tracer's wire-format spec lives in one source file shared
# between Sphinx, GitHub's repo browser, and any reader who wants raw
# text.
source_suffix = {
    ".rst": "restructuredtext",
    ".md":  "markdown",
}

# Cross-link unique section titles without manual labels.
autosectionlabel_prefix_document = True

# Light-touch external references; expand if we ever cite QEMU's docs
# or the Capstone Python bindings.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

templates_path = ["_templates"]
# README.md is for repo-browser readers; the rendered site doesn't
# need it (its content is repeated under the appropriate sections).
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "README.md"]

# Furo is a modern, mobile-friendly theme.  Falls back to alabaster
# (Sphinx default) if furo isn't installed so a casual `make html`
# without `pip install furo` still builds.
try:
    import furo  # noqa: F401
    html_theme = "furo"
except ImportError:
    html_theme = "alabaster"

# No custom CSS / images today; leave html_static_path unset so the
# theme's defaults apply.  Empty directories aren't preserved by git,
# so a stub _static/ wouldn't survive checkout on CI runners anyway.
html_static_path: list[str] = []
html_title = f"ChampSim Tracer v{release}"

# Render Python type hints inline so the decoder reference page reads
# like an API doc rather than a wall of prose.
autodoc_typehints = "description"

# ---------- LaTeX / PDF output ----------
#
# `make latexpdf` produces _build/latex/champsim_tracer.pdf for offline
# distribution.  Requires a working TeX install (texlive-xetex,
# texlive-latex-recommended, texlive-fonts-recommended, latexmk on
# Debian/Ubuntu).  See the Makefile for the full apt install line.

latex_engine = "xelatex"  # Better Unicode and font handling than pdflatex.

# Use the standard `makeindex` for the genindex page rather than
# Sphinx's xelatex default of `xindy`.  xindy is a separate binary
# (Debian package `xindy`, ~150 MB after pulling in clisp) that the
# index pages of an English-only doc don't actually need; without
# this override `make latexpdf` aborts with
# "Can't exec 'xindy': No such file or directory" on a stock
# texlive-xetex install.
latex_use_xindy = False

# (master_doc, target_filename, title, author, theme)
# Use the friendly "ChampSim Tracer" form in the rendered title so
# the cover page reads cleanly; the .tex / .pdf basename keeps the
# underscored directory name for ergonomic file naming.
latex_documents = [
    (
        "index",
        "champsim_tracer.tex",
        "ChampSim Tracer Documentation",
        author,
        "manual",
    ),
]

latex_elements = {
    "papersize":   "letterpaper",
    "pointsize":   "11pt",
    # Tighter top-of-chapter spacing and a sans-serif title block.
    # `preamble` is raw LaTeX dropped above \begin{document}.
    "preamble": r"""
\usepackage{titlesec}
\titleformat{\chapter}[hang]{\normalfont\sffamily\Huge\bfseries}{\thechapter.}{1em}{}
\titlespacing*{\chapter}{0pt}{-30pt}{20pt}
""",
    # Drop the empty pages Sphinx normally inserts between chapters
    # for a single-sided PDF; they're useful in print but waste pages
    # on screen.
    "extraclassoptions": "openany,oneside",
    # The auto_index extension populates the genindex with the
    # tracer's symbol vocabulary (GEN_OP_*, REG_*, CST_FID_*, …),
    # so leave the default \printindex emission in place.  An older
    # near-empty index was suppressed here; the override is no longer
    # needed.
}
