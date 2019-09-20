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

function(main)
    set(project_source_common_files
        src/utils.cpp
        src/utils.h
    )

    set(project_libraries
        extutils)
        #iptc)

    add_osquery_extension_ex("IptablesExtTable" "table" "iptables_ext"
        SOURCES ${project_source_common_files} src/iptables_ext.h src/iptables_ext.cpp
        INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
        MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/iptables_ext.h"
        LIBRARIES ${project_libraries} #ip4tc
    )

    add_osquery_extension_ex("Ip6tablesExtTable" "table" "ip6tables_ext"
        SOURCES ${project_source_common_files} src/ip6tables_ext.h src/ip6tables_ext.cpp
        INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
        MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/ip6tables_ext.h"
        LIBRARIES ${project_libraries} #ip6tc
    )

    add_osquery_extension_ex("IptablesPoliciesTable" "table" "iptables_policies"
        SOURCES ${project_source_common_files} src/iptables_policies.h src/iptables_policies.cpp
        INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
        MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/iptables_policies.h"
        LIBRARIES ${project_libraries} #ip4tc
    )

    add_osquery_extension_ex("Ip6tablesPoliciesTable" "table" "ip6tables_policies"
        SOURCES ${project_source_common_files} src/ip6tables_policies.h src/ip6tables_policies.cpp
        INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
        MAININCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/ip6tables_policies.h"
        LIBRARIES ${project_libraries} #ip6tc
    )

    set(project_test_files
        test/main.cpp
        test/utils.cpp
        src/utils.cpp
        src/utils.h)

    # AddTest("iptables" test_target_name ${project_test_files})

    set(test_target_name "tobExtTests_${PROJECT_NAME}")
    add_executable(${test_target_name} ${project_test_files})

    target_include_directories("${test_target_name}" PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )

    target_compile_definitions("${test_target_name}" PRIVATE "${configuration_root}")

    target_link_libraries("${test_target_name}" PRIVATE
      osquery_cxx_settings
      osquery_sdk_pluginsdk
      osquery_extensions_implthrift
      thirdparty_googletest
      thirdparty_googletest_headers
      thirdparty_libiptc
      extutils
    )

    # target_link_libraries("${test_target_name}" PRIVATE
    #  glog gflags thrift boost_system-mt boost_thread-mt boost_filesystem-mt rt
    #  boost_context-mt extutils iptc
    # )

    # target_link_libraries("${test_target_name}" PRIVATE "${CMAKE_BINARY_DIR}/osquery/libosquery.a")
endfunction()

main()
