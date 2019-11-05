# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.10)
project(iptables_ext)

function(iptablesMain)
  set(project_source_common_files
    src/utils.cpp
    src/utils.h
  )

  set(project_libraries_ipv4
    extutils
  )

  set(project_libraries_ipv6
    extutils
  )

  if(${OSQUERY_VERSION_INTERNAL} VERSION_LESS "4.0.1")
    set(project_libraries_ipv4
      ${project_libraries_ipv4}
      iptc
      ip4tc
    )

    set(project_libraries_ipv6
      ${project_libraries_ipv6}
      iptc
      ip6tc
    )
  endif()

  set(project_common_include_dirs
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${TOB_EXTENSIONS_ROOT}"
  )

  addOsqueryExtensionEx("IptablesExtTable" "table" "iptables_ext"
    SOURCES ${project_source_common_files} src/iptables_ext.h src/iptables_ext.cpp
    INCLUDEDIRS ${project_common_include_dirs}
    MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/iptables_ext.h"
    LIBRARIES ${project_libraries_ipv4}
  )

  addOsqueryExtensionEx("Ip6tablesExtTable" "table" "ip6tables_ext"
    SOURCES ${project_source_common_files} src/ip6tables_ext.h src/ip6tables_ext.cpp
    INCLUDEDIRS ${project_common_include_dirs}
    MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/ip6tables_ext.h"
    LIBRARIES ${project_libraries_ipv6}
  )

  addOsqueryExtensionEx("IptablesPoliciesTable" "table" "iptables_policies"
    SOURCES ${project_source_common_files} src/iptables_policies.h src/iptables_policies.cpp
    INCLUDEDIRS ${project_common_include_dirs}
    MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/iptables_policies.h"
    LIBRARIES ${project_libraries_ipv4}
  )

  addOsqueryExtensionEx("Ip6tablesPoliciesTable" "table" "ip6tables_policies"
    SOURCES ${project_source_common_files} src/ip6tables_policies.h src/ip6tables_policies.cpp
    INCLUDEDIRS ${project_common_include_dirs}
    MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/ip6tables_policies.h"
    LIBRARIES ${project_libraries_ipv6}
  )

  set(project_test_files
    test/main.cpp
    test/utils.cpp
    src/utils.cpp
    src/utils.h
  )

  AddTest("iptables" test_target_name ${project_test_files})

  target_include_directories("${test_target_name}" PRIVATE
    ${project_common_include_dirs}
  )

  target_compile_definitions("${test_target_name}" PRIVATE "${configuration_root}")

  if(${OSQUERY_VERSION_INTERNAL} VERSION_LESS "4.0.1")
    target_link_libraries("${test_target_name}" PRIVATE
      glog gflags thrift boost_system-mt boost_thread-mt boost_filesystem-mt rt
      boost_context-mt extutils iptc
    )

    target_link_libraries("${test_target_name}" PRIVATE "${CMAKE_BINARY_DIR}/osquery/libosquery.a")

  else()
    target_compile_options("${test_target_name}" PRIVATE ${cxx_settings})

    target_link_libraries("${test_target_name}" PRIVATE
      osquery_sdk_pluginsdk
      osquery_extensions_implthrift
      thirdparty_googletest
      thirdparty_libiptc
      extutils
    )
  endif()
endfunction()

iptablesMain()
