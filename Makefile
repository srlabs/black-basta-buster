DEPS := doc/after-bb.png   doc/edit-magic.png  doc/running-bb.png doc/chinook-diff.png  doc/find-magic.png  doc/win-mkfile.png doc/decrypted.png     doc/hexeditor.png doc/decrypt.png       doc/no-magic.png

RST2HTML_FLAGS =
RST2PDF_FLAGS =
RINHO_FLAGS =


all: README.pdf README.html

README.pdf: $(DEPS)

README.html: $(DEPS)

%.html: %.rst
	rst2html $(RST2HTML_FLAGS)  $<  $@

%.pdf: %.rst
	command -v  rinoh &&  rinoh $(RINHO_FLAGS)  $<  ||  rst2pdf $(RST2PDF_FLAGS)  $<  $@

%.png: %.svg
	rsvg-convert $<  >  $@


README := 2023-12-srlabs-black-basta-buster-readme.pdf
REPORT := 2023-08-srlabs-Black-Basta-Buster-report.pdf
GIT_ZIP := 2023-12-srlabs-black-basta-buster-v3.zip
$(GIT_ZIP): .git/HEAD $(REPORT)
	git archive --format=zip --output=$@ HEAD
	zip -u ./$@  $(README)


2023-10-srlabs-black-basta-bundle.zip: $(GIT_ZIP) $(REPORT) tobias@srlabs.de.pgp.asc
	zip -u ./$@  $^
