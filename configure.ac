AC_INIT([tlmsp-tools], [0.1], [], [])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT

AC_PROG_CC

want_debug=no
AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--enable-debug], [Enable debug build options])
  AC_HELP_STRING([--disable-debug], [Disable debug build options]),
  [want_debug=$enableval])
if test "$want_debug" = "yes"; then
  CFLAGS="$CFLAGS -O0 -g"
fi

AC_ARG_WITH([pki-dir],
  [AS_HELP_STRING([--with-pki-dir=DIR], [Directory in which to look for relative-path public PKI files [SYSCONFDIR/pki]])],
  [],
  [with_pki_dir='${sysconfdir}/pki'])
AC_SUBST([pki_dir], [$with_pki_dir])

AC_ARG_WITH([pki-private-dir],
  [AS_HELP_STRING([--with-pki-private-dir=DIR], [Directory in which to look for relative-path private PKI files [SYSCONFDIR/pki/private]])],
  [],
  [with_pki_private_dir='${sysconfdir}/pki/private'])
AC_SUBST([pki_private_dir], [$with_pki_private_dir])

# Placed before the adjustment of CPPFLAGS to ensure the headers for
# the version specified on the command line are ahead of any system
# versions in the include path.
AC_LIB_HAVE_LINKFLAGS(ssl, [crypto], [#include <openssl/tlmsp.h>], [TLMSP_method();]) 

AC_LIB_HAVE_LINKFLAGS(ev, [], [#include <ev.h>], [ev_run(EV_DEFAULT_ EVRUN_NOWAIT);]) 
AC_LIB_HAVE_LINKFLAGS(pcre2-8, [], [
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
], [pcre2_config_8(0, NULL);]) 

AC_CONFIG_SUBDIRS([libucl])

AX_CHECK_DEFINE([signal.h], [SIGINFO], [
  AC_DEFINE(HAVE_SIGINFO, 1, Define to 1 if you have SIGINFO.)
])

# libtlmsp-cfg tracing
#AC_DEFINE(TRACE_ENABLED)

AC_OUTPUT([Makefile])
