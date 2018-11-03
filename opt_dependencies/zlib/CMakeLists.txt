cmake_minimum_required(VERSION 3.12)
project(zlib)

set(ZLIB_REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src")

function(zlibMain)
  add_library("${PROJECT_NAME}" STATIC EXCLUDE_FROM_ALL
    "${ZLIB_REPOSITORY_ROOT}/adler32.c"
    "${ZLIB_REPOSITORY_ROOT}/crc32.c"
    "${ZLIB_REPOSITORY_ROOT}/deflate.c"
    "${ZLIB_REPOSITORY_ROOT}/gzclose.c"
    "${ZLIB_REPOSITORY_ROOT}/gzlib.c"
    "${ZLIB_REPOSITORY_ROOT}/gzwrite.c"
    "${ZLIB_REPOSITORY_ROOT}/inffast.c"
    "${ZLIB_REPOSITORY_ROOT}/inffixed.h"
    "${ZLIB_REPOSITORY_ROOT}/inflate.h"
    "${ZLIB_REPOSITORY_ROOT}/inftrees.h"
    "${ZLIB_REPOSITORY_ROOT}/trees.h"
    "${ZLIB_REPOSITORY_ROOT}/zconf.h"
    "${ZLIB_REPOSITORY_ROOT}/zutil.c"
    "${ZLIB_REPOSITORY_ROOT}/compress.c"
    "${ZLIB_REPOSITORY_ROOT}/crc32.h"
    "${ZLIB_REPOSITORY_ROOT}/deflate.h"
    "${ZLIB_REPOSITORY_ROOT}/gzguts.h"
    "${ZLIB_REPOSITORY_ROOT}/gzread.c"
    "${ZLIB_REPOSITORY_ROOT}/infback.c"
    "${ZLIB_REPOSITORY_ROOT}/inffast.h"
    "${ZLIB_REPOSITORY_ROOT}/inflate.c"
    "${ZLIB_REPOSITORY_ROOT}/inftrees.c"
    "${ZLIB_REPOSITORY_ROOT}/trees.c"
    "${ZLIB_REPOSITORY_ROOT}/uncompr.c"
    "${ZLIB_REPOSITORY_ROOT}/zlib.h"
    "${ZLIB_REPOSITORY_ROOT}/zutil.h"
  )

  target_include_directories("${PROJECT_NAME}" PUBLIC "${ZLIB_REPOSITORY_ROOT}")
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error -g0)

  add_library(z ALIAS zlib)
endfunction()

zlibMain()
