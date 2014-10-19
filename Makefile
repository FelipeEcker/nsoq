#/*......,,,,,,,...................................................
#*
#* @@NAME:     MAKEFILE
#* @@VERSION:  4.0
#* @@DESC:     Compilation file (this file is part of Nsoq tool).
#* @@AUTHOR:   Felipe Ecker (khun) <khun@hexcodes.org>
#* @@DATE:     18/10/2014 (06:30:00)
#* @@MANIFEST:
#*      Copyright (C) Felipe Ecker 2003-2014.
#*      You should have received a copy of the GNU General Public
#*      License inside this program. Licensed under GPL 3.
#*      If not, write to me an e-mail please. Thank you.
#*
#*.................................................................
#*/

include Makefile.in

all: nsoq

.PHONY : nsoq
nsoq: $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) $(OPTIM) $(STATICFLAG)

%.o : %.c
	$(CC) -S $< $(FLAGS) $(OPTIM) -o $@.asm
	$(CC) -c $< $(FLAGS) $(OPTIM) -o $@

static: $(OBJS_STATIC)
ifdef DARWIN_SYSTEM
	$(error "System doesn't support static compilation.")
else
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) $(OPTIM) --static
endif

%.o-static : %.c
	$(CC) -S $< $(FLAGS) $(OPTIM) -o $@.asm -static
	$(CC) -c $< $(FLAGS) $(OPTIM) -o $@ --static

debug: $(OBJS_DEBUG)
	mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$(NAME) $(SRCDIR)/$(MAIN_SOURCE) $^ $(LDFLAGS) $(DBGOPTIM)

%.od : %.c
	$(CC) -S $< $(FLAGS) $(DBGOPTIM) -o $@.asm
	$(CC) -c $< $(FLAGS) $(DBGOPTIM) -o $@


.PHONY : install
install:
	install -m755 $(BINDIR)/nsoq $(INSTALLDIR)
	mkdir -p $(MANDIR)
	install -m644 $(DOC)/nsoq.8.gz $(MANDIR)
	mkdir -p $(DOCDIR)
	install -m644 $(DOC)/COPYING $(DOCDIR)
	install -m644 $(DOC)/nsoq.txt $(DOCDIR)


uninstall:
	rm -rf $(MANDIR)/nsoq.8.gz $(DOCDIR) $(INSTALLDIR)/nsoq 


.PHONY : clean
clean:
	rm -rf *~ *.tar.gz *.tar.bz2 *.deb *.spec *.rpm $(SRCDIR)/*~ $(SRCDIR)/*.o $(SRCDIR)/*.o-static $(SRCDIR)/*.od $(SRCDIR)/*.asm $(BINDIR) $(DESTDIR) $(DEBDIR) $(RPMDIR)


pack: clean
	mkdir -p $(DESTDIR)
	cp -Rfa Makefile.in Makefile INSTALL $(DOC) include src $(DESTDIR)/
	tar cfz $(PKG) $(DESTDIR)
	rm -rf $(DESTDIR)


# Building a DEB package.
deb: clean nsoq
	mkdir -p $(DEBBUILD)/DEBIAN
	cp $(DOC)/app_deb.in $(DEBBUILD)/DEBIAN/control
	mkdir -p $(DEBBUILD)$(INSTALLDIR)
	install -m 755 $(BINDIR)/nsoq $(DEBBUILD)$(INSTALLDIR)
	mkdir -p $(DEBBUILD)$(DOCDIR)
	install -m644 $(DOC)/nsoq.txt $(DEBBUILD)$(DOCDIR)
	install -m644 $(DOC)/COPYING $(DEBBUILD)$(DOCDIR)
	mkdir -p $(DEBBUILD)$(MANDIR)
	install -m644 $(DOC)/nsoq.8.gz $(DEBBUILD)$(MANDIR)
	mkdir -p $(DEBDIR)
	dpkg-deb -b $(DEBBUILD) $(DEBDIR)/$(DEBPKG)
	rm -rf rm -rf $(SRCDIR)/*~ $(SRCDIR)/*.o $(SRCDIR)/*.asm $(DESTDIR) $(BINDIR) $(DEBBUILD)
	echo "[Done] deb package wrote on: $(DEBDIR)/$(DEBPKG)\n"


# Building a RPM package.
dist: clean nsoq
	mkdir -p $(DESTDIR)
	mkdir -p $(DESTDIR)$(INSTALLDIR)
	install -m 755 $(BINDIR)/nsoq $(DESTDIR)$(INSTALLDIR)
	mkdir -p $(DESTDIR)$(DOCDIR)
	install -m644 $(DOC)/nsoq.txt $(DESTDIR)$(DOCDIR)
	install -m644 $(DOC)/COPYING $(DESTDIR)$(DOCDIR)
	mkdir -p $(DESTDIR)$(MANDIR)
	install -m644 $(DOC)/nsoq.8.gz $(DESTDIR)$(MANDIR)
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
