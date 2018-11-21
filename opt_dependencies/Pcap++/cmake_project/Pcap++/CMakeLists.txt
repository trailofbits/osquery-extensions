cmake_minimum_required(VERSION 3.12)
project(Pcap++)

function(PcapPlusPlusMain)
  set(public_headers_folder "${PCAPPLUSPLUS_ROOT}/Pcap++/header")

  set(public_header_files
    "${public_headers_folder}/Device.h"
    "${public_headers_folder}/DpdkDevice.h"
    "${public_headers_folder}/DpdkDeviceList.h"
    "${public_headers_folder}/NetworkUtils.h"
    "${public_headers_folder}/PcapDevice.h"
    "${public_headers_folder}/PcapFileDevice.h"
    "${public_headers_folder}/PcapFilter.h"
    "${public_headers_folder}/PcapLiveDevice.h"
    "${public_headers_folder}/PcapLiveDeviceList.h"
    "${public_headers_folder}/PcapRemoteDevice.h"
    "${public_headers_folder}/PcapRemoteDeviceList.h"
    "${public_headers_folder}/PfRingDevice.h"
    "${public_headers_folder}/PfRingDeviceList.h"
    "${public_headers_folder}/RawSocketDevice.h"
    "${public_headers_folder}/WinPcapLiveDevice.h"
  )

  set(source_files
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/DpdkDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/DpdkDeviceList.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/NetworkUtils.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapFileDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapFilter.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapLiveDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapLiveDeviceList.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapRemoteDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PcapRemoteDeviceList.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PfRingDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/PfRingDeviceList.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/RawSocketDevice.cpp"
    "${PCAPPLUSPLUS_ROOT}/Pcap++/src/WinPcapLiveDevice.cpp"
  )

  set(public_include_folders
    "${public_headers_folder}"
    "${PCAPPLUSPLUS_ROOT}/../netinet"
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files} ${public_header_files})
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error)
  target_include_directories("${PROJECT_NAME}" PUBLIC ${public_include_folders})
  target_compile_definitions("${PROJECT_NAME}" PUBLIC LINUX)
  target_link_libraries("${PROJECT_NAME}" PUBLIC pcap Common++ Packet++ light_pcapng)
endfunction()

PcapPlusPlusMain()
