# Tools
TEX=pdflatex
BIBTEX=bibtex

# Main input file (without extension)
MAIN=main
# Output PDF name
OUT=practical_3_cos_330

.PHONY: all clean distclean FORCE

# Default target
all: $(OUT).pdf

# Always rebuild PDF
$(OUT).pdf: FORCE
	$(TEX) -jobname=$(OUT) $(MAIN).tex
	$(BIBTEX) $(OUT)
	$(TEX) -jobname=$(OUT) $(MAIN).tex
	$(TEX) -jobname=$(OUT) $(MAIN).tex

# Clean auxiliary files
clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot practical_3_cos_330.pfd

# Full clean, including PDF
distclean: clean
	rm -f $(OUT).pdf

FORCE:
