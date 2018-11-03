cmake_minimum_required(VERSION 3.12)

set(BUILD_DEPS "/usr/local/osquery")

function(importLLVM)
  list(APPEND CMAKE_PREFIX_PATH "${BUILD_DEPS}/llvm-bpf")

  foreach(lib LLVM Clang)
    find_package("${lib}" CONFIG REQUIRED HINTS "${BUILD_DEPS}/llvm-bpf")
  endforeach()

  list(GET LLVM_LIBRARY_DIRS 0 llvm_lib_folder)

  if(EXISTS "${llvm_lib_folder}/libclang.a")
    set(libclang_library "${llvm_lib_folder}/libclang.a")
  elseif(EXISTS "${llvm_lib_folder}/libclang.so")
    set(libclang_library "${llvm_lib_folder}/libclang.so")
  else()
    message(FATAL_ERROR "Failed to locate libclang in ${llvm_lib_folder}")
  endif()

  string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
  list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
  list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

  add_library(llvm_libraries INTERFACE)

  target_include_directories(llvm_libraries INTERFACE ${LLVM_INCLUDE_DIRS})

  target_compile_definitions(llvm_libraries INTERFACE
    ${LLVM_DEFINITIONS}
    LLVM_MINOR_VERSION=${LLVM_MINOR_VERSION}
    LLVM_MAJOR_VERSION=${LLVM_MAJOR_VERSION}
  )

  llvm_map_components_to_libnames(llvm_libs
   ipo irreader mcjit orcjit executionengine
   debuginfodwarf ${LLVM_TARGETS_TO_BUILD}
  )

  target_link_libraries(llvm_libraries INTERFACE ${llvm_libs})

  set(clang_library_names
    "${libclang_library}"
    ${CMAKE_DL_LIBS}
    clangAST
    clangAnalysis
    clangBasic
    clangDriver
    clangEdit
    clangFormat
    clangFrontend
    clangIndex
    clangLex
    clangParse
    clangRewrite
    clangSema
    clangSerialization
    clangToolingCore
    clangCodeGen
  )

  target_link_libraries(llvm_libraries INTERFACE
    ${llvm_libraries} ${clang_library_names}
  )
endfunction()

importLLVM()
