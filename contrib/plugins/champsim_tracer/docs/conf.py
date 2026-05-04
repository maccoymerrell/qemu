# Sphinx configuration for the champsim_tracer documentation.
#
# Build:
#     pip install sphinx furo
#     make -C contrib/plugins/champsim_tracer/docs html
#
# Output lands in contrib/plugins/champsim_tracer/docs/_build/html.

project = "champsim_tracer"
author = "QEMU champsim_tracer plugin contributors"
copyright = "2026, " + author

# Read the trace format version from the C header so the docs and the
# wire format never drift.  The format spec page references this.
import re
import os

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
html_title = f"champsim_tracer v{release}"

# Render Python type hints inline so the decoder reference page reads
# like an API doc rather than a wall of prose.
autodoc_typehints = "description"
