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
project(fwctl)

function(main)
  set(project_libraries
    firewall
    hostsfile
  )

  if(UNIX)
    list(APPEND project_libraries
      boost_system-mt
      boost_serialization-mt
      boost_regex-mt
    )
  else()
    list(APPEND project_libraries
      libboost_system-mt-s.lib
      libboost_serialization-mt-s.lib
      libboost_regex-mt-s.lib
    )
  endif()

  set(project_common_source_files
    src/globals.h
    src/globals.cpp

    src/basetable.h
  )

  add_osquery_extension_ex("HostBlacklistTable" "table" "HostBlacklist"
    SOURCES ${project_common_source_files} src/hostblacklist.h src/hostblacklist.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES hostblacklist.h
    LIBRARIES ${project_libraries}
  )

  add_osquery_extension_ex("PortBlacklistTable" "table" "PortBlacklist"
    SOURCES ${project_common_source_files} src/portblacklist.h src/portblacklist.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES portblacklist.h
    LIBRARIES ${project_libraries}
  )

  # Only enable table tests on Linux and macOS
  if(UNIX AND NOT DEFINED SKIP_TESTS)
    set(project_test_files

      tests/main.cpp
      tests/hostblacklist.cpp

      src/globals.h
      src/globals.cpp

      src/basetable.h

      src/hostblacklist.h
      src/hostblacklist.cpp

      src/portblacklist.h
      src/portblacklist.cpp
    )

    AddTest("tables" test_target_name ${project_test_files})
    target_include_directories("${test_target_name}" PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )

    target_compile_definitions("${test_target_name}" PRIVATE "${configuration_root}")

    target_link_libraries("${test_target_name}" PRIVATE
      glog gflags thrift boost_system-mt boost_thread-mt boost_filesystem-mt boost_context-mt
      firewall hostsfile
    )

    target_link_libraries("${test_target_name}" PRIVATE "${CMAKE_BINARY_DIR}/osquery/libosquery.a")

    if(NOT APPLE)
      target_link_libraries("${test_target_name}" PRIVATE rt)
    endif()
  endif()
endfunction()

main()

