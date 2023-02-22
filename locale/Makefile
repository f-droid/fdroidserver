
FILES = ../fdroid $(wildcard ../fdroidserver/*.py) \
	$(wildcard /usr/lib/python3.*/argparse.py) \
	$(wildcard /usr/lib/python3.*/optparse.py) \
	$(wildcard /usr/lib/python3.*/getopt.py)

# these are the supported languages
ALL_LINGUAS = $(shell sed -En 's,include locale/([^/]+)/.*,\1,p' ../MANIFEST.in)
POFILES = $(wildcard */LC_MESSAGES/fdroidserver.po)
MOFILES = $(ALL_LINGUAS:=/LC_MESSAGES/fdroidserver.mo)

TEMPLATE = fdroidserver.pot

VERSION = $(shell git describe)

OPTS = --no-wrap --sort-output --add-location=file

default:
	@printf "Build the translation files using: ./setup.py compile_catalog\n\n"

message:
	@printf "\nYou probably want to use this instead: ./setup.py compile_catalog\n\n"

# refresh everything from the source code
update: $(POFILES)

# generate .mo files from the .po files
compile: message $(MOFILES)

clean:
	-rm -f -- $(MOFILES)
	-rm -f -- $(POFILES:=~)

# to remove obsolete source strings, run xgettext without --join-existing
$(TEMPLATE): $(FILES)
	xgettext --join-existing --from-code=UTF-8 \
		--language=Python --keyword=_ \
		$(OPTS) --output=$(TEMPLATE) \
		--package-name="fdroidserver" --package-version=$(VERSION) \
		--foreign-user \
		--msgid-bugs-address=https://gitlab.com/fdroid/fdroidserver/issues \
		$(FILES)
	msguniq $(OPTS) --use-first \
		--output-file=$(TEMPLATE) $(TEMPLATE)
	sed -i 's,CHARSET,UTF-8,' $(TEMPLATE)

%.po: $(TEMPLATE)
	msgattrib --set-obsolete --ignore-file=$(TEMPLATE) -o $@ $@
	msgattrib $(OPTS) --no-obsolete --output-file=$@ $@
	msguniq $(OPTS) --use-first --output-file=$@ $@
	msgmerge $(OPTS) --update $@ $(TEMPLATE)

%/LC_MESSAGES/fdroidserver.mo: %/LC_MESSAGES/fdroidserver.po
	msgfmt --check -o $@ $(@:mo=po)


.PHONY = compile clean update
