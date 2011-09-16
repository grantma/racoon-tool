DESTDIR =

# 
# Installation Makefile for racoon-tool
#
# This could be a bit rude! FIXME!

PREFIX=/usr/local
CONFDIR=$(DESTDIR)$(PREFIX)/etc/racoon
SBINDIR=$(DESTDIR)$(PREFIX)/sbin
MANDIR=$(DESTDIR)$(PREFIX)/man
INSTALL=/usr/bin/install

dummy:
	echo "BLeep!"

install-man:
	- mkdir -p $(MANDIR)
	- mkdir -p $(MANDIR)/man5
	- mkdir -p $(MANDIR)/man8
	$(INSTALL) racoon-tool.8 $(MANDIR)/man8
	$(INSTALL) racoon-tool.conf.5 $(MANDIR)/man5

install: dummy install-man
	- mkdir -p $(SBINDIR)
	- mkdir -p $(CONFDIR)
	$(INSTALL) -m 755 racoon-tool.pl $(SBINDIR)/racoon-tool
	@if [ ! -f $(CONFDIR)/racoon-tool.conf ]; then \
		$(INSTALL) -m 644 -b racoon-tool.conf $(CONFDIR) ; \
	fi

uninstall:
	- rm -f $(SBINDIR)/racoon-tool
	- rm -f $(MANDIR)/man8/racoon-tool.8
	- rm -f $(MANDIR)/man5/racoon-tool.conf.5
