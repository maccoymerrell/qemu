# champsim_tracer documentation

Sphinx project for the champsim_tracer plugin. Build it locally
with:

```sh
pip install sphinx furo myst-parser
make -C contrib/plugins/champsim_tracer/docs html
```

Output lands in `_build/html/`. Open `_build/html/index.html` in a
browser.

## Contents

* `quickstart.rst` — building, running, plugin options, decoder
  invocation.
* `architecture.rst` — subsystem map, CP and WP flow loops, caveats
  every prospective modifier needs to know.
* `extending.rst` — step-by-step guides for adding generic opcodes,
  register IDs, branch types, and dynamic fields.
* `format.rst` — wraps `champsim_tracer_format.md` (the canonical
  wire-format spec) so it reads as a Sphinx page.
* `reference.rst` — symbolic ID tables (generic opcodes, branch
  types, registers, sync events, field IDs, ISA codes).
* `decoder.rst` — Python decoder library and `cst_audit.py` CLI.

## Hosting

The site is intended for GitHub Pages. A typical workflow under
`.github/workflows/docs.yml` checks out the repo, installs Sphinx,
runs `make html`, and pushes the `_build/html` tree to the
`gh-pages` branch. The Sphinx build does not require a working QEMU
build, only `pip install sphinx furo myst-parser`.
