# Minimal Sphinx makefile for the champsim_tracer docs.
#
#   make html      # build the HTML site under _build/html
#   make clean     # wipe _build
#   make linkcheck # validate external URLs
#
# Requires: pip install sphinx furo

SPHINXOPTS    ?= -W --keep-going
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

.PHONY: help html clean linkcheck Makefile

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

html clean linkcheck:
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
