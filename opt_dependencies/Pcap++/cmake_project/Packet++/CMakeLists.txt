cmake_minimum_required(VERSION 3.12)
project(Packet++)

function(PacketPlusPlusMain)
  set(public_headers_folder "${PCAPPLUSPLUS_ROOT}/Packet++/header")

  set(public_header_files
    "${public_headers_folder}/ArpLayer.h"
    "${public_headers_folder}/DhcpLayer.h"
    "${public_headers_folder}/DnsLayerEnums.h"
    "${public_headers_folder}/DnsLayer.h"
    "${public_headers_folder}/DnsResourceData.h"
    "${public_headers_folder}/DnsResource.h"
    "${public_headers_folder}/EthLayer.h"
    "${public_headers_folder}/GreLayer.h"
    "${public_headers_folder}/HttpLayer.h"
    "${public_headers_folder}/IcmpLayer.h"
    "${public_headers_folder}/IgmpLayer.h"
    "${public_headers_folder}/IPReassembly.h"
    "${public_headers_folder}/IPv4Layer.h"
    "${public_headers_folder}/IPv6Extensions.h"
    "${public_headers_folder}/IPv6Layer.h"
    "${public_headers_folder}/Layer.h"
    "${public_headers_folder}/MplsLayer.h"
    "${public_headers_folder}/NullLoopbackLayer.h"
    "${public_headers_folder}/Packet.h"
    "${public_headers_folder}/PacketTrailerLayer.h"
    "${public_headers_folder}/PacketUtils.h"
    "${public_headers_folder}/PayloadLayer.h"
    "${public_headers_folder}/PPPoELayer.h"
    "${public_headers_folder}/ProtocolType.h"
    "${public_headers_folder}/RadiusLayer.h"
    "${public_headers_folder}/RawPacket.h"
    "${public_headers_folder}/SdpLayer.h"
    "${public_headers_folder}/SipLayer.h"
    "${public_headers_folder}/SllLayer.h"
    "${public_headers_folder}/SSLCommon.h"
    "${public_headers_folder}/SSLHandshake.h"
    "${public_headers_folder}/SSLLayer.h"
    "${public_headers_folder}/TcpLayer.h"
    "${public_headers_folder}/TcpReassembly.h"
    "${public_headers_folder}/TextBasedProtocol.h"
    "${public_headers_folder}/TLVData.h"
    "${public_headers_folder}/UdpLayer.h"
    "${public_headers_folder}/VlanLayer.h"
    "${public_headers_folder}/VxlanLayer.h"
  )

  set(source_files
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/ArpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/DhcpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/DnsLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/DnsResource.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/DnsResourceData.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/EthLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/GreLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/HttpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IcmpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IgmpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IPReassembly.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IPv4Layer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IPv6Extensions.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/IPv6Layer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/Layer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/MplsLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/NullLoopbackLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/Packet.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/PacketTrailerLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/PacketUtils.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/PayloadLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/PPPoELayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/RadiusLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/RawPacket.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/SdpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/SipLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/SllLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/SSLHandshake.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/SSLLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/TcpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/TcpReassembly.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/TextBasedProtocol.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/TLVData.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/UdpLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/VlanLayer.cpp"
    "${PCAPPLUSPLUS_ROOT}/Packet++/src/VxlanLayer.cpp"
  )

  set(public_include_folders
    "${public_headers_folder}"
    "${PCAPPLUSPLUS_ROOT}/../netinet"
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files} ${public_header_files})
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-error)
  target_include_directories("${PROJECT_NAME}" PUBLIC ${public_include_folders})
  target_compile_definitions("${PROJECT_NAME}" PUBLIC LINUX)
  target_link_libraries("${PROJECT_NAME}" PUBLIC Common++ EndianPortable)

  target_compile_options("${PROJECT_NAME}" INTERFACE -Wno-shadow)
endfunction()

PacketPlusPlusMain()
