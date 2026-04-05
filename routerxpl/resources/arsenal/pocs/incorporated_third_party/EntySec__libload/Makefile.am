ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wextra -Werror -O2

lib_LTLIBRARIES = libload.la
bin_PROGRAMS = llpack
loadincludedir = $(includedir)
loadinclude_HEADERS = include/libload.h include/llbin.h

libload_la_CFLAGS = $(AM_CFLAGS)
libload_la_CPPFLAGS = -I$(top_srcdir)/include
libload_la_LDFLAGS = -version-info 0:0:0

if PLATFORM_MACOS
libload_la_SOURCES = src/macho.c src/inject.c
endif

if PLATFORM_LINUX
libload_la_SOURCES = \
	src/elf.c \
	src/elf_inject.c \
	src/entry_x86_64.S \
	src/entry_aarch64.S \
	src/entry_x86.S \
	src/entry_arm.S \
	src/entry_mips.S \
	src/entry_sparc.S
libload_la_LIBADD = -ldl
endif

llpack_SOURCES = tools/llpack.c
llpack_CFLAGS = $(AM_CFLAGS)
llpack_CPPFLAGS = -I$(top_srcdir)/include
