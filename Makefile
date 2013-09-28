#/*......,,,,,,,...................................................
#*
#* @@NAME:     MAKEFILE
#* @@VERSION:  3.0
#* @@DESC:     Compilation file (this file is part of MpTcp tool).
#* @@AUTHOR:   Felipe Ecker (khun) <khun@hexcodes.org>
#* @@DATE:     15/09/2012 (01:30:00)
#* @@MANIFEST:
#*      Copyright (C) Felipe Ecker 2003-2013.
#*      You should have received a copy of the GNU General Public
#*      License inside this program. Licensed under GPL 3.
#*      If not, write to me an e-mail please. Thank you.
#*
#*.................................................................
#*/

include Makefile.in

all: mptcp

.PHONY : mptcp
mptcp: $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) $(STATICFLAG)

%.o : %.c
	$(CC) -S $< $(FLAGS) -o $@.asm
	$(CC) -c $< $(FLAGS) -o $@

static: $(OBJS_STATIC)
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) --static

%.o-static : %.c
	$(CC) -S $< $(FLAGS) -o $@.asm --static
	$(CC) -c $< $(FLAGS) -o $@ --static

debug: $(OBJS_DEBUG)
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) -DDEBUG -ggdb

%.od : %.c
	$(CC) -S $< $(FLAGS) -o $@.asm -ggdb
	$(CC) -c $< $(FLAGS) -o $@ -DDEBUG -ggdb


.PHONY : install
install:
	install -m755 $(BINDIR)/mptcp $(INSTALLDIR)
	mkdir -p $(MANDIR)
	install -m644 $(DOC)/mptcp.8.gz $(MANDIR)
	mkdir -p $(DOCDIR)
	install -m644 $(DOC)/COPYING $(DOCDIR)
	install -m644 $(DOC)/mptcp.txt $(DOCDIR)


uninstall:
	rm -rf $(MANDIR)/mptcp.8.gz $(DOCDIR) $(INSTALLDIR)/mptcp 


.PHONY : clean
clean:
	rm -rf *~ *.tar.gz *.tar.bz2 *.deb *.spec *.rpm $(SRCDIR)/*~ $(SRCDIR)/*.o $(SRCDIR)/*.o-static $(SRCDIR)/*.od $(SRCDIR)/*.asm $(BINDIR) $(DESTDIR) $(DEBDIR) $(RPMDIR)


pack: clean
	mkdir -p $(DESTDIR)
	cp -Rfa Makefile.in Makefile INSTALL $(DOC) include src $(DESTDIR)/
	tar cfz $(PKG) $(DESTDIR)
	rm -rf $(DESTDIR)


# Building a DEB package.
deb: clean mptcp
	mkdir -p $(DEBBUILD)/DEBIAN
	cp $(DOC)/pkg_deb.in $(DEBBUILD)/DEBIAN/control
	mkdir -p $(DEBBUILD)$(INSTALLDIR)
	install -m 755 $(BINDIR)/mptcp $(DEBBUILD)$(INSTALLDIR)
	mkdir -p $(DEBBUILD)$(DOCDIR)
	install -m644 $(DOC)/mptcp.txt $(DEBBUILD)$(DOCDIR)
	install -m644 $(DOC)/COPYING $(DEBBUILD)$(DOCDIR)
	mkdir -p $(DEBBUILD)$(MANDIR)
	install -m644 $(DOC)/mptcp.8.gz $(DEBBUILD)$(MANDIR)
	mkdir -p $(DEBDIR)
	dpkg-deb -b $(DEBBUILD) $(DEBDIR)/$(DEBPKG)
	rm -rf rm -rf $(SRCDIR)/*~ $(SRCDIR)/*.o $(SRCDIR)/*.asm $(DESTDIR) $(BINDIR) $(DEBBUILD)
	echo "[Done] deb package wrote on: $(DEBDIR)/$(DEBPKG)\n"


# Building a RPM package.
dist: clean mptcp
	mkdir -p $(DESTDIR)
	mkdir -p $(DESTDIR)$(INSTALLDIR)
	install -m 755 $(BINDIR)/mptcp $(DESTDIR)$(INSTALLDIR)
	mkdir -p $(DESTDIR)$(DOCDIR)
	install -m644 $(DOC)/mptcp.txt $(DESTDIR)$(DOCDIR)
	install -m644 $(DOC)/COPYING $(DESTDIR)$(DOCDIR)
	mkdir -p $(DESTDIR)$(MANDIR)
	install -m644 $(DOC)/mptcp.8.gz $(DESTDIR)$(MANDIR)
	tar -C $(PWD)/$(DESTDIR) -czhf $(SRCTAR) .

spec: $(SPECIN)
	sed s/@@APPNAME@@/$(NAME)/g $(SPECIN) | \
	sed s:@@BINDIR@@:$(INSTALLDIR):g | \
	sed s:@@MANDIR@@:$(MANDIR):g | \
	sed s:@@DOCDIR@@:$(DOCDIR):g | \
	sed s/@@DESTDIR@@/$(RPMDIR)/g | \
	sed s/@@MAJOR@@/$(MAJOR)/g | \
	sed s/@@MINOR@@/$(MINOR)/g | \
	sed s/@@PATCH@@/$(PATCH)/g | \
	sed s/@@RELEASE@@/$(BUILD)/g > $(SPECFILE)

rpm: dist spec
	rpmbuild -bb -v --clean --rmspec --rmsource $(RPMDEFS) $(SPECFILE)
	rm -rf $(SRCDIR)/*~ $(SRCDIR)/*.o $(SRCDIR)/*.asm $(DESTDIR) $(BINDIR)
