# Minimal Sphinx makefile for the champsim_tracer docs.
#
#   make html       # HTML site at _build/html
#   make latexpdf   # PDF at _build/latex/champsim_tracer.pdf
#   make clean      # wipe _build
#   make linkcheck  # validate external URLs
#
# Requires (all targets):  pip install sphinx furo myst-parser
# Additionally for PDF:    a working TeX install with xelatex and
#                          latexmk on PATH.  On Debian/Ubuntu:
#                            sudo apt install texlive-xetex \
#                                texlive-latex-recommended \
#                                texlive-fonts-recommended latexmk
#
# Note on -W escalation:  HTML uses -W --keep-going so a CI miss
# trips the build, but latexpdf shells out to latexmk and noisy
# LaTeX warnings (overfull hbox, missing fonts) routinely fire on
# perfectly-correct documents.  Drop -W for latexpdf so a font
# substitution doesn't fail the PDF build.

SPHINXOPTS    ?= -W --keep-going
PDFOPTS       ?= --keep-going
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

.PHONY: help html clean linkcheck latex latexpdf pdf Makefile

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

html clean linkcheck latex:
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# pdf is an alias for latexpdf for users who don't know Sphinx's
# target naming convention.
pdf: latexpdf

latexpdf:
	@$(SPHINXBUILD) -M latexpdf "$(SOURCEDIR)" "$(BUILDDIR)" $(PDFOPTS) $(O)
	@echo "PDF: $(BUILDDIR)/latex/champsim_tracer.pdf"
