
FILES = ../fdroid $(wildcard ../fdroidserver/*.py) \
	$(wildcard /usr/lib/python3.*/argparse.py) \
	$(wildcard /usr/lib/python3.*/optparse.py) \
	$(wildcard /usr/lib/python3.*/getopt.py)

# these are the supported languages
ALL_LINGUAS = de es pt_BR pt_PT tr zh_Hans zh_Hant
POFILES = $(wildcard */LC_MESSAGES/fdroidserver.po)
MOFILES = $(ALL_LINGUAS:=/LC_MESSAGES/fdroidserver.mo)

TEMPLATE = fdroidserver.pot

VERSION = $(shell git describe)

# refresh everything from the source code
update: $(POFILES)

# generate .mo files from the .po files
compile: $(MOFILES)

clean:
	-rm -f -- $(MOFILES)
	-rm -f -- $(POFILES:=~)

$(TEMPLATE): $(FILES)
	xgettext --join-existing --from-code=UTF-8 \
		--language=Python --keyword=_ \
		--no-wrap --sort-output --add-location=file --output=$(TEMPLATE) \
		--package-name="fdroidserver" --package-version=$(VERSION) \
		--foreign-user \
		--msgid-bugs-address=https://gitlab.com/fdroid/fdroidserver/issues \
		$(FILES)
	sed -i 's,CHARSET,UTF-8,' $(TEMPLATE)

%.po: $(TEMPLATE)
	msgmerge --no-wrap --sort-output --add-location=file --update $@ $(TEMPLATE)

%/LC_MESSAGES/fdroidserver.mo: %/LC_MESSAGES/fdroidserver.po
	msgfmt --check -o $@ $(@:mo=po)


.PHONY = compile clean update
