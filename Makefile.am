SUBDIRS = libucl

LIBUCL_LDADD = libucl/src/.libs/libucl.a

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = \
	-DLIBDEMO_PKI_DIR=\"$(pki_dir)\" \
	-DLIBDEMO_PKI_PRIVATE_DIR=\"$(pki_private_dir)\" \
	-I$(top_srcdir)/libtlmsp-cfg \
	-I$(top_srcdir)/libtlmsp-util \
	-I$(top_srcdir)/libucl/include
AM_CFLAGS = -Wall -Wextra -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-strict-aliasing -Werror

noinst_PROGRAMS = test-parse
bin_PROGRAMS = \
	tlmsp-client \
	tlmsp-mb \
	tlmsp-server
lib_LTLIBRARIES = \
	libtlmsp-util.la \
	libtlmsp-cfg.la

libtlmsp_cfg_la_SOURCES = \
	libtlmsp-cfg/api.c \
	libtlmsp-cfg/format.c \
	libtlmsp-cfg/openssl.c \
	libtlmsp-cfg/parse.c \
	libtlmsp-cfg/print.c
libtlmsp_cfg_la_LIBADD = \
	libtlmsp-util.la
libtlmsp_cfg_la_LDFLAGS = -export-symbols-regex '^tlmsp_cfg_'

libtlmsp_util_la_SOURCES = \
	libtlmsp-util/address.c \
	libtlmsp-util/file.c
libtlmsp_util_la_LDFLAGS = -export-symbols-regex '^tlmsp_util_'

# Libraries that don't get installed
noinst_LIBRARIES = libdemo.a
libdemo_a_SOURCES = \
	libdemo/activity.c \
	libdemo/activity.h \
	libdemo/app.c \
	libdemo/app.h \
	libdemo/connection.c \
	libdemo/connection.h \
	libdemo/container_queue.c \
	libdemo/container_queue.h \
	libdemo/pki.c \
	libdemo/pki.h \
	libdemo/print.c \
	libdemo/print.h \
	libdemo/splice.c \
	libdemo/splice.h \
	libdemo/signal.c \
	libdemo/signal.h

test_parse_SOURCES = libtlmsp-cfg/test-parse.c
test_parse_LDADD = \
	libtlmsp-cfg.la \
	$(LIBUCL_LDADD) \
	$(LTLIBSSL)

tlmsp_client_SOURCES = \
	client/client.c
tlmsp_client_LDADD = \
	libdemo.a \
	libtlmsp-cfg.la \
	libtlmsp-util.la \
	$(LIBUCL_LDADD) \
	$(LTLIBEV) \
	$(LTLIBPCRE2_8) \
	$(LTLIBSSL)

tlmsp_mb_SOURCES = \
	middlebox/middlebox.c
tlmsp_mb_LDADD = \
	libdemo.a \
	libtlmsp-cfg.la \
	libtlmsp-util.la \
	$(LIBUCL_LDADD) \
	$(LTLIBEV) \
	$(LTLIBPCRE2_8) \
	$(LTLIBSSL)

tlmsp_server_SOURCES = \
	server/server.c
tlmsp_server_LDADD = \
	libdemo.a \
	libtlmsp-cfg.la \
	libtlmsp-util.la \
	$(LIBUCL_LDADD) \
	$(LTLIBEV) \
	$(LTLIBPCRE2_8) \
	$(LTLIBSSL)

pkginclude_HEADERS = \
	libtlmsp-cfg/libtlmsp-cfg.h \
	libtlmsp-cfg/libtlmsp-cfg-openssl.h \
	libtlmsp-util/libtlmsp-util.h



install-data-local:
	$(mkinstalldirs) $(datadir)/examples
	-for file in $(srcdir)/examples/*.ucl; do \
		basefile=$$(basename $$file); \
		$(INSTALL_DATA) $$file $(datadir)/examples/$$basefile; \
	done
