EXTRA_DIST = mod_dav_access.c mod_dav_access.spec

all-local:
	$(APXS) "-Wc,${CFLAGS}" -c $(DEF_LDLIBS) $(AM_CFLAGS) $(AM_LDFLAGS) @srcdir@/mod_dav_access.c

install-exec-local: 
	if test -z "$${LIBEXECDIR}"; then LIBEXECDIR=`$(APXS) -q LIBEXECDIR`; fi;\
	\
	mkdir -p $(DESTDIR)$${LIBEXECDIR}; \
	\
	$(APXS) "-Wc,${CFLAGS}" -S LIBEXECDIR=$(DESTDIR)$${LIBEXECDIR} -c -i $(DEF_LDLIBS) $(AM_CFLAGS) $(AM_LDFLAGS) @srcdir@/mod_dav_access.c

