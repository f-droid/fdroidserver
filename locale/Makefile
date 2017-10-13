
FILES = ../fdroid $(wildcard ../fdroidserver/*.py)

# these are the supported languages
ALL_LINGUAS = de es pt_BR pt_PT tr zh_Hans zh_Hant
POFILES = $(ALL_LINGUAS:=/LC_MESSAGES/fdroidserver.po)
MOFILES = $(ALL_LINGUAS:=/LC_MESSAGES/fdroidserver.mo)

TEMPLATE = fdroidserver.pot

VERSION = $(shell git describe)

# generate .mo files from the .po files
all-local: $(MOFILES)

clean-local:
	-rm -f -- $(MOFILES)
	-rm -f -- $(POFILES:=~)

# refresh the template from the source code
template: $(TEMPLATE)

$(TEMPLATE): $(FILES)
	xgettext --join-existing --from-code=UTF-8 \
		--language=Python --keyword=_ \
		--sort-output --add-location=file --output=$(TEMPLATE) \
		--package-name="fdroidserver" --package-version=$(VERSION) \
		--foreign-user \
		--msgid-bugs-address=https://gitlab.com/fdroid/fdroidserver/issues \
		$(FILES)
	sed -i 's,CHARSET,UTF-8,' $(TEMPLATE)

%/LC_MESSAGES/fdroidserver.mo: %/LC_MESSAGES/fdroidserver.po
	msgfmt --check -o $@ $(@:mo=po)


.PHONY = all-local clean-local template
