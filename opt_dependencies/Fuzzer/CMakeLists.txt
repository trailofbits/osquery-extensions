cmake_minimum_required(VERSION 3.10)

set(BUILD_DEPS "/usr/local/osquery")
set(LLVM_VERSION "7.0.1")

function(checkEnvironment)
  set(expected_c_compiler "${BUILD_DEPS}/bin/clang")
  set(expected_cxx_compiler "${BUILD_DEPS}/bin/clang++")
  set(expected_ld_library_path "${BUILD_DEPS}/lib")
  set(expected_ldflags "-L${BUILD_DEPS}/legacy/lib -L${BUILD_DEPS}/lib -B${BUILD_DEPS}/legacy/lib -rtlib=compiler-rt -fuse-ld=lld")

  set(check_succeeded True)

  if(NOT "${CMAKE_C_COMPILER}" STREQUAL "${expected_c_compiler}")
    message(STATUS "The C compiler is not correctly set")
    list(APPEND export_entry_list "  export CC=\"${expected_c_compiler}\"")

    set(check_succeeded False)
  endif()

  if(NOT "${CMAKE_CXX_COMPILER}" STREQUAL "${expected_cxx_compiler}")
    message(STATUS "The C++ compiler is not correctly set")
    list(APPEND export_entry_list "  export CXX=\"${expected_cxx_compiler}\"")

    set(check_succeeded False)
  endif()

  if(NOT "$ENV{LD_LIBRARY_PATH}" STREQUAL "${expected_ld_library_path}")
    message(STATUS "The LD_LIBRARY_PATH environment variable is not correctly set (required by tablegen)")
    list(APPEND export_entry_list "  export LD_LIBRARY_PATH=\"${expected_ld_library_path}\"")

    set(check_succeeded False)
  endif()

  if(NOT "$ENV{LDFLAGS}" STREQUAL "${expected_ldflags}")
    message(STATUS "The LDFLAGS environment variable is not correctly set")
    list(APPEND export_entry_list "  export LDFLAGS=\"${expected_ldflags}\"")

    set(check_succeeded False)
  endif()

  if(NOT ${check_succeeded})
    message("=====")
    message("Please fix your environment by copying and pasting the following export entries:")

    foreach(export_entry ${export_entry_list})
      message("${export_entry}")
    endforeach()

    message("=====")
    message(FATAL_ERROR "Aborting...")
  endif()
endfunction()

function(importLibFuzzer)
  checkEnvironment()

  set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .dylib .so .a)
  set(CMAKE_SKIP_RPATH TRUE)
  set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a .dylib .so)
  set(CMAKE_CXX_FLAGS "-std=c++14 -stdlib=libc++" CACHE STRING "Default CXX flags" FORCE)

  add_compile_options(
    -march=x86-64
    -mno-avx
  )

  list(APPEND CMAKE_PREFIX_PATH "${DEPS_DIR}/lib/cmake/libxml2")

  include_directories(SYSTEM "${CMAKE_SOURCE_DIR}/third-party/sysroots/linux")

  set(CMAKE_REQUIRED_INCLUDES
    "${BUILD_DEPS}/legacy/include"
    "${BUILD_DEPS}/include"
  )

  include_directories(SYSTEM "${BUILD_DEPS}/include/c++/v1")
  include_directories(SYSTEM "${BUILD_DEPS}/legacy/include")
  include_directories(SYSTEM "${BUILD_DEPS}/include")
  include_directories(SYSTEM "${BUILD_DEPS}/lib/clang/4.0.0/include")

  set(source_folder_name "compiler-rt-${LLVM_VERSION}.src")
  set(tarball_name "${source_folder_name}.tar.xz")

  add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${tarball_name}"
    COMMAND curl "http://releases.llvm.org/${LLVM_VERSION}/${tarball_name}" -O > /dev/null 2>&1
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Downloading: ${tarball_name}"
    VERBATIM
  )

  add_custom_target(libfuzzer_source_downloader DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${tarball_name}")

  set(source_file_list
    FuzzerCrossOver.cpp
    FuzzerDataFlowTrace.cpp
    FuzzerDriver.cpp
    FuzzerExtFunctionsDlsym.cpp
    FuzzerExtFunctionsDlsymWin.cpp
    FuzzerExtFunctionsWeakAlias.cpp
    FuzzerExtFunctionsWeak.cpp
    FuzzerExtraCounters.cpp
    FuzzerIO.cpp
    FuzzerIOPosix.cpp
    FuzzerIOWindows.cpp
    FuzzerLoop.cpp
    FuzzerMain.cpp
    FuzzerMerge.cpp
    FuzzerMutate.cpp
    FuzzerSHA1.cpp
    FuzzerShmemFuchsia.cpp
    FuzzerShmemPosix.cpp
    FuzzerShmemWindows.cpp
    FuzzerTracePC.cpp
    FuzzerUtil.cpp
    FuzzerUtilDarwin.cpp
    FuzzerUtilFuchsia.cpp
    FuzzerUtilLinux.cpp
    FuzzerUtilPosix.cpp
    FuzzerUtilWindows.cpp
  )
  foreach(source_file ${source_file_list})
    list(APPEND libfuzzer_sources
      "${CMAKE_CURRENT_BINARY_DIR}/${source_folder_name}/lib/fuzzer/${source_file}"
    )
  endforeach()

  add_custom_command(
    OUTPUT ${libfuzzer_sources}
    DEPENDS libfuzzer_source_downloader
    COMMAND tar xf "${tarball_name}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Downloading: ${tarball_name}"
    VERBATIM
  )

  add_library(Fuzzer STATIC
    ${libfuzzer_sources}
  )

  target_include_directories(Fuzzer PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/${source_folder_name}/lib/fuzzer"
  )

  target_compile_options(Fuzzer PRIVATE
    -g
    -O2
    -fno-omit-frame-pointer
    -Wno-error
  )

  target_compile_options(Fuzzer INTERFACE
    -fsanitize=fuzzer,address
    -g3
    -O0
  )

  target_compile_features(Fuzzer PRIVATE cxx_std_11)

  target_link_libraries(Fuzzer PUBLIC
    -stdlib=libc++
    c++abi
  )
endfunction()

importLibFuzzer()
