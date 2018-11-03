cmake_minimum_required(VERSION 3.10)

set(BUILD_DEPS "/usr/local/osquery")
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
set(LLVM_CLANG_VERSION "7.0.1")

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
    message(FATAL_ERROR "Please delete everything in the build folder and try again")
  endif()
endfunction()

function(downloadLLVM)
  set(llvm_tarball_name "llvm-${LLVM_CLANG_VERSION}.src.tar.xz")
  set(llvm_tarball_path "${CMAKE_CURRENT_BINARY_DIR}/${llvm_tarball_name}")

  add_custom_command(
    OUTPUT "${llvm_tarball_path}"
    COMMAND curl "http://releases.llvm.org/${LLVM_CLANG_VERSION}/${llvm_tarball_name}" -o "${llvm_tarball_path}"
    VERBATIM
  )

  set(cfe_tarball_name "cfe-${LLVM_CLANG_VERSION}.src.tar.xz")
  set(cfe_tarball_path "${CMAKE_CURRENT_BINARY_DIR}/${cfe_tarball_name}")

  add_custom_command(
    OUTPUT "${cfe_tarball_path}"
    COMMAND curl "http://releases.llvm.org/${LLVM_CLANG_VERSION}/${cfe_tarball_name}" -o "${cfe_tarball_path}"
    VERBATIM
  )

  add_custom_target(
    download_llvm_tarballs
    DEPENDS "${llvm_tarball_path}" "${cfe_tarball_path}"
  )
endfunction()

function(decompressLLVM)
  downloadLLVM()

  set(llvm_root_folder "${CMAKE_CURRENT_SOURCE_DIR}/llvm-${LLVM_CLANG_VERSION}.src")
  
  add_custom_command(
    OUTPUT "${llvm_root_folder}"
    DEPENDS download_llvm_tarballs
    COMMAND "${CMAKE_COMMAND}" -E tar xf "${CMAKE_CURRENT_BINARY_DIR}/llvm-${LLVM_CLANG_VERSION}.src.tar.xz"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  )

  add_custom_target(
    extract_llvm_tarball
    DEPENDS "${llvm_root_folder}"
  )

  set(cfe_root_folder "${CMAKE_CURRENT_SOURCE_DIR}/llvm-${LLVM_CLANG_VERSION}.src/tools/cfe-${LLVM_CLANG_VERSION}.src")

  add_custom_command(
    OUTPUT "${cfe_root_folder}"
    DEPENDS extract_llvm_tarball
    COMMAND "${CMAKE_COMMAND}" -E tar xf "${CMAKE_CURRENT_BINARY_DIR}/cfe-${LLVM_CLANG_VERSION}.src.tar.xz"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/llvm-${LLVM_CLANG_VERSION}.src/tools"
  )

  add_custom_target(
    extract_clang_tarball
    DEPENDS "${cfe_root_folder}"
  )

  set(clang_tool_folder "${CMAKE_CURRENT_SOURCE_DIR}/llvm-${LLVM_CLANG_VERSION}.src/tools/clang")

  add_custom_command(
    OUTPUT "${clang_tool_folder}"
    DEPENDS extract_clang_tarball
    COMMAND "${CMAKE_COMMAND}" -E rename "${cfe_root_folder}" "${clang_tool_folder}"
    VERBATIM
  )

  add_custom_target(
    init_llvm_source
    DEPENDS "${clang_tool_folder}"
  )
endfunction()

function(importLLVM)
  checkEnvironment()
  decompressLLVM()

  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${BUILD_DEPS}/llvm-bpf" CACHE PATH "Install path" FORCE)
  endif()

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
  include_directories(SYSTEM "${BUILD_DEPS}/lib/clang/6.0.0/include")

  set(LLVM_TARGETS_TO_BUILD "X86;BPF" CACHE STRING "The LLVM LLVM_TARGETS_TO_BUILD setting" FORCE)

  set(variables_to_disable
    LLVM_INCLUDE_UTILS
    LLVM_BUILD_UTILS
    LLVM_INSTALL_UTILS
    LLVM_ENABLE_TERMINFO
    LLVM_INCLUDE_TESTS
    LLVM_INCLUDE_EXAMPLES
    CLANG_INCLUDE_TESTS
    CLANG_INCLUDE_DOCS
  )

  set(variables_to_enable
    LLVM_ENABLE_RTTI
    LIBCLANG_BUILD_STATIC
    LLVM_INCLUDE_TOOLS
    LLVM_BUILD_TOOLS
    LLVM_INSTALL_TOOLS
    LLVM_ENABLE_LIBCXX
    HAVE_CXX_ATOMICS_WITHOUT_LIB
    HAVE_CXX_ATOMICS64_WITH_LIB
  )

  foreach(variable_name ${variables_to_enable})
    set(${variable_name} ON CACHE BOOL "The LLVM ${variable_name} setting" FORCE)
  endforeach()

  foreach(variable_name ${variables_to_disable})
    set(${variable_name} OFF CACHE BOOL "The LLVM ${variable_name} setting" FORCE)
  endforeach()

  set(llvm_source_folder "${CMAKE_CURRENT_SOURCE_DIR}/llvm-${LLVM_CLANG_VERSION}.src")
  if(EXISTS "${llvm_source_folder}")
    add_subdirectory("llvm-${LLVM_CLANG_VERSION}.src" "llvm")
  else()
    message(STATUS "The LLVM source folder was not found. Please run `make init_llvm_source` and then re-run CMake")
  endif()

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/llvm/lib/libclang.a" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
endfunction()

importLLVM()
