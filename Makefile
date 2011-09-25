DESTDIR =

# 
# Installation Makefile for racoon-tool
#
# This could be a bit rude! FIXME!

OSNAME := $(shell uname -s)
ifeq ($(OSNAME),Linux)
  PREFIX=/usr
  CONFDIR=/etc/racoon
  VARCONFDIR=/var/lib/racoon
else ifeq ($(OSNAME), FreeBSD)
  PREFIX=/usr/local
  CONFDIR=$(PREFIX)/etc/racoon
  VARCONFDIR=/var/db/racoon
else
  PREFIX=/usr/local
  CONFDIR=$(PREFIX)/etc/racoon
  VARCONFDIR=/usr/local/ipsec-tools/var
endif
SBINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/man
INSTALL=/usr/bin/install
IPSEC_TOOLS_VERSION = 0.8.0
IPSEC_TOOLS_DEBDIR = ../ipsec-tools-$(IPSEC_TOOLS_VERSION)/debian

MANPAGES := racoon-tool.8 racoon-tool.conf.5

all: manpages

manpages: $(MANPAGES)

%.5: %.5.in
	perl -pe 's#\@\@CONFDIR\@\@#$(CONFDIR)#' < $< > $@
	perl -i -pe 's#\@\@VARCONFDIR\@\@#$(VARCONFDIR)#' $@
	
%.8: %.8.in
	perl -pe 's#\@\@CONFDIR\@\@#$(CONFDIR)#' < $< > $@
	perl -i -pe 's#\@\@VARCONFDIR\@\@#$(VARCONFDIR)#' $@ 

clean: 
	- rm -f $(MANPAGES)

install-man: manpages
	- mkdir -p $(MANDIR)
	- mkdir -p $(MANDIR)/man5
	- mkdir -p $(MANDIR)/man8
	$(INSTALL) racoon-tool.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) racoon-tool.conf.5 $(DESTDIR)$(MANDIR)/man5

install: install-man
	- mkdir -p $(SBINDIR)
	- mkdir -p $(CONFDIR)
	$(INSTALL) -m 755 racoon-tool.pl $(DESTDIR)$(SBINDIR)/racoon-tool
	@if [ ! -f $(CONFDIR)/racoon-tool.conf ]; then \
		$(INSTALL) -m 644 -b racoon-tool.conf $(DESTDIR)$(CONFDIR) ; \
	fi

install-debian: manpages
	$(INSTALL) -m 644 racoon-tool.pl $(IPSEC_TOOLS_DEBDIR)
	$(INSTALL) -m 644 racoon-tool.8 $(IPSEC_TOOLS_DEBDIR)
	$(INSTALL) -m 644 racoon-tool.conf.5 $(IPSEC_TOOLS_DEBDIR)
	$(INSTALL) -m 644 racoon-tool.conf $(IPSEC_TOOLS_DEBDIR)

uninstall:
	- rm -f $(SBINDIR)/racoon-tool
	- rm -f $(MANDIR)/man8/racoon-tool.8
	- rm -f $(MANDIR)/man5/racoon-tool.conf.5
