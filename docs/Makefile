DOC := notes

.PHONY: all pdf clean

all: pdf

pdf: $(DOC).pdf

$(DOC).pdf: $(DOC).tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(DOC).tex

clean:
	latexmk -C
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.fls *.fdb_latexmk *.synctex.gz
