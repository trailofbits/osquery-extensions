cmake_minimum_required(VERSION 3.12)
project(Common++)

function(CommonPlusPlusMain)
  set(public_headers_folder "${PCAPPLUSPLUS_ROOT}/Common++/header")

  set(public_header_files
    "${public_headers_folder}/GeneralUtils.h"
    "${public_headers_folder}/IpAddress.h"
    "${public_headers_folder}/IpUtils.h"
    "${public_headers_folder}/Logger.h"
    "${public_headers_folder}/LRUList.h"
    "${public_headers_folder}/MacAddress.h"
    "${public_headers_folder}/PcapPlusPlusVersion.h"
    "${public_headers_folder}/PlatformSpecificUtils.h"
    "${public_headers_folder}/PointerVector.h"
    "${public_headers_folder}/SystemUtils.h"
    "${public_headers_folder}/TablePrinter.h"
  )

  set(source_files
    "${PCAPPLUSPLUS_ROOT}/Common++/src/GeneralUtils.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/IpAddress.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/IpUtils.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/Logger.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/MacAddress.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/PcapPlusPlusVersion.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/SystemUtils.cpp"
    "${PCAPPLUSPLUS_ROOT}/Common++/src/TablePrinter.cpp"
  )

  set(public_include_folders
    "${public_headers_folder}"
    "${PCAPPLUSPLUS_ROOT}/../netinet"
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files} ${public_header_files})
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error)
  target_include_directories("${PROJECT_NAME}" SYSTEM PUBLIC ${public_include_folders})
  target_compile_definitions("${PROJECT_NAME}" PUBLIC LINUX)
endfunction()

CommonPlusPlusMain()
