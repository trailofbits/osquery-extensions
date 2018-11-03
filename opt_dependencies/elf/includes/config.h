/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Building with -fsanitize=undefined or not */
#define CHECK_UNDEFINED 0

/* Should ar and ranlib use -D behavior by default? */
#define DEFAULT_AR_DETERMINISTIC false

/* Define to 1 if you have the declaration of `mempcpy', and to 0 if you
   don't. */
#define HAVE_DECL_MEMPCPY 1

/* Define to 1 if you have the declaration of `memrchr', and to 0 if you
   don't. */
#define HAVE_DECL_MEMRCHR 1

/* Define to 1 if you have the declaration of `powerof2', and to 0 if you
   don't. */
#define HAVE_DECL_POWEROF2 1

/* Define to 1 if you have the declaration of `rawmemchr', and to 0 if you
   don't. */
#define HAVE_DECL_RAWMEMCHR 1

/* Defined if __attribute__((fallthrough)) is supported */
#define HAVE_FALLTHROUGH 1

/* Defined if __attribute__((gcc_struct)) is supported */
#define HAVE_GCC_STRUCT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `process_vm_readv' function. */
#define HAVE_PROCESS_VM_READV 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if <sys/user.h> defines struct user_regs_struct */
#define HAVE_SYS_USER_REGS 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Defined if __attribute__((visibility())) is supported */
#define HAVE_VISIBILITY 1

/* $libdir subdirectory containing libebl modules. */
#define LIBEBL_SUBDIR "elfutils"

/* Identifier for modules in the build. */
#define MODVERSION "Build for elfutils 174 x86_64-pc-linux-gnu"

/* Name of package */
#define PACKAGE "elfutils"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://sourceware.org/bugzilla"

/* Define to the full name of this package. */
#define PACKAGE_NAME "elfutils"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "elfutils 0.174"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "elfutils"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://elfutils.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.174"

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Support bzip2 decompression via -lbz2. */
/* #undef USE_BZLIB */

/* Defined if demangling is enabled */
#define USE_DEMANGLE 1

/* Defined if libraries should be thread-safe. */
/* #undef USE_LOCKS */

/* Support LZMA (xz) decompression via -llzma. */
/* #undef USE_LZMA */

/* Support gzip decompression via -lz. */
#define USE_ZLIB 1

/* Version number of package */
#define VERSION "0.174"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

#include <eu-config.h>
