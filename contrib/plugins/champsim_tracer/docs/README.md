# champsim_tracer documentation

Sphinx project for the champsim_tracer plugin.

Build the HTML site:

```sh
pip install sphinx furo myst-parser
make -C contrib/plugins/champsim_tracer/docs html
# open _build/html/index.html
```

Build a PDF for offline use (requires a TeX install):

```sh
sudo apt install texlive-xetex texlive-latex-recommended \
                 texlive-fonts-recommended fonts-freefont-otf \
                 latexmk
make -C contrib/plugins/champsim_tracer/docs latexpdf
# _build/latex/champsim_tracer.pdf
```

(`fonts-freefont-otf` provides FreeSerif, which the xelatex template
selects as the default body face. `texlive-fonts-recommended` alone
doesn't include it.)

`make pdf` is an alias for `make latexpdf`. `make help` lists every
target Sphinx supports (epub, man, etc.) — those work but are
unconfigured.

## Contents

* `quickstart.rst` — building, running, plugin options, decoder
  invocation.
* `architecture.rst` — subsystem map, CP and WP flow loops, caveats
  every prospective modifier needs to know.
* `extending.rst` — step-by-step guides for adding generic opcodes,
  register IDs, branch types, and dynamic fields.
* `format.rst` — the canonical wire-format spec: the decoder recipe
  (Part I) and the byte-level reference (Part II).
* `reference.rst` — symbolic ID tables (generic opcodes, branch
  types, registers, sync events, field IDs, ISA codes).
* `decoder.rst` — `cst_decode` (objdump-style and legacy text dumps)
  and `cst_audit` (byte-budget breakdown).  Both are C++ binaries
  built alongside the plugin.

## Hosting

The site is intended for GitHub Pages. A typical workflow under
`.github/workflows/docs.yml` checks out the repo, installs Sphinx,
runs `make html`, and pushes the `_build/html` tree to the
`gh-pages` branch. The Sphinx build does not require a working QEMU
build, only `pip install sphinx furo myst-parser`.
