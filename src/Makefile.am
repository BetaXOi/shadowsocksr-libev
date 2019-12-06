VERSION_INFO = 2:0:0

AM_CFLAGS = -g -O2 -Wall -Wno-deprecated-declarations -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
AM_CFLAGS += $(PTHREAD_CFLAGS)
if !USE_SYSTEM_SHARED_LIB
AM_CFLAGS += -I$(top_srcdir)/libev
AM_CFLAGS += -I$(top_srcdir)/libudns
AM_CFLAGS += -I$(top_srcdir)/libsodium/src/libsodium/include
endif
AM_CFLAGS += -I$(top_srcdir)/libipset/include
AM_CFLAGS += -I$(top_srcdir)/libcork/include
AM_CFLAGS += $(LIBPCRE_CFLAGS)

SS_COMMON_LIBS = $(top_builddir)/libipset/libipset.la \
                 $(top_builddir)/libcork/libcork.la \
                 $(INET_NTOP_LIB) $(LIBPCRE_LIBS)
if USE_SYSTEM_SHARED_LIB
SS_COMMON_LIBS += -lev -lsodium -lm
else
SS_COMMON_LIBS += $(top_builddir)/libev/libev.la \
                  $(top_builddir)/libsodium/src/libsodium/libsodium.la
endif

bin_PROGRAMS = ssr-local
#bin_PROGRAMS += ssr-tunnel
if !BUILD_WINCOMPAT
#bin_PROGRAMS += ssr-server ssr-manager
endif

sni_src = http.c \
          tls.c \
          rule.c

ssr_local_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   encrypt.c \
                   udprelay.c \
                   cache.c \
                   acl.c \
                   netutils.c \
                   local.c \
                   $(sni_src)

#ssr_tunnel_SOURCES = utils.c \
#                    jconf.c \
#                    json.c \
#                    encrypt.c \
#                    udprelay.c \
#                    cache.c \
#                    netutils.c \
#                    tunnel.c
#
#ssr_server_SOURCES = utils.c \
#                    netutils.c \
#                    jconf.c \
#                    json.c \
#                    encrypt.c \
#                    udprelay.c \
#                    cache.c \
#                    acl.c \
#                    resolv.c \
#                    server.c \
#                    $(sni_src)
#
#ssr_manager_SOURCES = utils.c \
#                     jconf.c \
#                     json.c \
#                     manager.c

ssr_local_LDADD = $(SS_COMMON_LIBS)
#ssr_tunnel_LDADD = $(SS_COMMON_LIBS)
#ssr_server_LDADD = $(SS_COMMON_LIBS)
#ssr_manager_LDADD = $(SS_COMMON_LIBS)
if USE_SYSTEM_SHARED_LIB
ssr_local_LDADD += -ludns
#ssr_tunnel_LDADD += -ludns
#ssr_server_LDADD += -ludns
else
ssr_local_LDADD += $(top_builddir)/libudns/libudns.la
#ssr_tunnel_LDADD += $(top_builddir)/libudns/libudns.la
#ssr_server_LDADD += $(top_builddir)/libudns/libudns.la
endif

ssr_local_CFLAGS = $(AM_CFLAGS) -DMODULE_LOCAL
#ssr_tunnel_CFLAGS = $(AM_CFLAGS) -DMODULE_TUNNEL
#ssr_server_CFLAGS = $(AM_CFLAGS) -DMODULE_REMOTE
#ssr_manager_CFLAGS = $(AM_CFLAGS) -DMODULE_MANAGER

if BUILD_WINCOMPAT
ssr_local_SOURCES += win32.c
#ssr_tunnel_SOURCES += win32.c
endif

if BUILD_REDIRECTOR
bin_SCRIPTS = ssr-nat
bin_PROGRAMS += ssr-redir
ssr_redir_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   encrypt.c \
                   netutils.c \
                   cache.c \
                   udprelay.c \
                   redir.c \
                   $(sni_src)
ssr_redir_CFLAGS = $(AM_CFLAGS) -DMODULE_REDIR
ssr_redir_LDADD = $(SS_COMMON_LIBS)
if USE_SYSTEM_SHARED_LIB
ssr_redir_LDADD += -ludns
else
ssr_redir_LDADD += $(top_builddir)/libudns/libudns.la
endif
endif

lib_LTLIBRARIES = libshadowsocks-libev.la
libshadowsocks_libev_la_SOURCES = $(ssr_local_SOURCES)
libshadowsocks_libev_la_CFLAGS = $(ssr_local_CFLAGS) -DLIB_ONLY
libshadowsocks_libev_la_LDFLAGS = -version-info $(VERSION_INFO)
libshadowsocks_libev_la_LIBADD = $(ssr_local_LDADD)
include_HEADERS = shadowsocks.h
