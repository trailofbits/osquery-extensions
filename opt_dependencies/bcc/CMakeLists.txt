cmake_minimum_required(VERSION 3.12)
project(bcc)

set(BCC_REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src")

function(bccMain)
  importDependency(llvm_libraries)
  importDependency(flexBison)
  importDependency(zlib)
  importDependency(elf)

  BISON_TARGET(Parser "${CMAKE_CURRENT_SOURCE_DIR}/patches/parser.yy"
    "${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc"
    COMPILE_FLAGS "-o ${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc -v --debug"
  )

  FLEX_TARGET(Lexer "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b/lexer.ll"
    "${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc"
    COMPILE_FLAGS "--c++ --o ${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc"
  )

  add_library("${PROJECT_NAME}" STATIC
    # "bcc" library
    "${BCC_REPOSITORY_ROOT}/src/cc/bpf_common.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/bpf_module.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/exported_files.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/bcc_debug.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/table_storage.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/bpffs_table.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/json_map_decl_visitor.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/ns_guard.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/common.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/link_all.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/usdt/usdt.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/usdt/usdt_args.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/shared_table.cc"

    # "bpf" library
    "${BCC_REPOSITORY_ROOT}/src/cc/libbpf.c"
    "${BCC_REPOSITORY_ROOT}/src/cc/perf_reader.c"

    # "bcc-loader" library
    "${BCC_REPOSITORY_ROOT}/src/cc/bcc_syms.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/bcc_elf.c"
    "${BCC_REPOSITORY_ROOT}/src/cc/bcc_perf_map.c"
    "${BCC_REPOSITORY_ROOT}/src/cc/bcc_proc.c"

    # "clang_frontend" library
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/clang/loader.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/clang/b_frontend_action.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/clang/tp_frontend_action.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/clang/kbuild_helper.cc"

    # "b_frontend" library
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/loader.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/type_check.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b/codegen_llvm.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b/node.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b/parser.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b/printer.cc"
    ${BISON_Parser_OUTPUTS}
    ${FLEX_Lexer_OUTPUTS}

    # API
    "${BCC_REPOSITORY_ROOT}/src/cc/api/BPF.cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/api/BPFTable.cc"
  )

  target_include_directories("${PROJECT_NAME}" PUBLIC
    "${BCC_REPOSITORY_ROOT}/src/cc/compat"
    "${BCC_REPOSITORY_ROOT}/src/cc"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/clang"
    "${BCC_REPOSITORY_ROOT}/src/cc/frontends/b"
    "${BCC_REPOSITORY_ROOT}/src/cc/api"
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  target_compile_definitions("${PROJECT_NAME}" PUBLIC
    BCC_PROG_TAG_DIR="/var/tmp/bcc"
    KERNEL_MODULES_DIR="/lib/modules"
  )

  target_link_libraries("${PROJECT_NAME}" PUBLIC
    elf
    llvm_libraries
  )

  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error -fvisibility=default -g0)
endfunction()

bccMain()
