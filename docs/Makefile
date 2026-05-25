DOCS := notes eli5

.PHONY: all pdf clean

all: pdf

pdf: $(addsuffix .pdf,$(DOCS))

%.pdf: %.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error $<

clean:
	latexmk -C
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.fls *.fdb_latexmk *.synctex.gz
