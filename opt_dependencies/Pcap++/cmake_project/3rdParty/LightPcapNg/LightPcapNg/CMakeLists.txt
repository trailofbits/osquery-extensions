cmake_minimum_required(VERSION 3.12)
project(light_pcapng)

function(LightPcapNgMain)
  set(public_headers_folder "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/include")

  set(public_header_files
    "${public_headers_folder}/light_debug.h"
    "${public_headers_folder}/light_internal.h"
    "${public_headers_folder}/light_pcapng_ext.h"
    "${public_headers_folder}/light_pcapng.h"
    "${public_headers_folder}/light_platform.h"
    "${public_headers_folder}/light_special.h"
    "${public_headers_folder}/light_types.h"
    "${public_headers_folder}/light_util.h"
  )

  set(source_files
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_advanced.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_alloc.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_internal.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_io.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_manipulate.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_option.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_pcapng.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_pcapng_cont.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_pcapng_ext.c"
    "${PCAPPLUSPLUS_ROOT}/3rdParty/LightPcapNg/LightPcapNg/src/light_platform.c"
  )

  set(public_include_folders
    "${public_headers_folder}"
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files} ${public_header_files})
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error)
  target_include_directories("${PROJECT_NAME}" SYSTEM PUBLIC ${public_include_folders})
endfunction()

LightPcapNgMain()
