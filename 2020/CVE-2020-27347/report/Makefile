# Main document name (without extension)
TEX = report

# Tools
LATEX    = pdflatex
BIBER    = biber
LATEXMK  = latexmk
ENTR     = entr

# Flags
LATEXFLAGS   = -interaction=nonstopmode -halt-on-error
LATEXMKFLAGS = -pdf -pvc -quiet

# Source files to watch (add more if needed)
WATCH_SRC = $(TEX).tex report_style.sty refs.bib

.PHONY: all clean watch

all: $(TEX).pdf

# Build sequence: LaTeX → Biber → LaTeX ×2
$(TEX).pdf: $(TEX).tex report_style.sty refs.bib
	@echo "==> Running pdflatex pass 1"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex
	@echo "==> Running biber"
	$(BIBER) $(TEX) || true
	@echo "==> Running pdflatex pass 2"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex
	@echo "==> Running pdflatex pass 3"
	$(LATEX) $(LATEXFLAGS) $(TEX).tex

# Continuous build: prefer latexmk, else fall back to entr
watch:
ifdef LATEXMK
	@echo "==> Watching with latexmk - press Ctrl-C to stop"
	$(LATEXMK) $(LATEXMKFLAGS) $(TEX).tex
else
	@echo "==> Watching with entr (press Ctrl-C to stop)"
	# requires `ls` and `entr` installed: ls *.tex *.sty refs.bib | entr -c make
	@ls $(WATCH_SRC) | $(ENTR) -c make
endif

clean:
	@echo "==> Cleaning auxiliary files"
	rm -f \
	  $(TEX).aux \
	  $(TEX).bbl \
	  $(TEX).bcf \
	  $(TEX).blg \
	  $(TEX).fdb_latexmk \
	  $(TEX).fls \
	  $(TEX).log \
	  $(TEX).out \
	  $(TEX).run.xml \
	  $(TEX).toc \
	  $(TEX).pdf
