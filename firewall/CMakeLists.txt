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

cmake_minimum_required(VERSION 3.9.1)
project(fwctl)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

function(main)
  set(PROJECT_SOURCEFILES
    src/main.cpp

    src/globals.h
    src/globals.cpp

    src/basetable.h

    src/hostblacklist.h
    src/hostblacklist.cpp

    src/portblacklist.h
    src/portblacklist.cpp
  )

  ADD_OSQUERY_EXTENSION("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})

  if(DEFINED APPLE OR DEFINED UNIX)
    set(configuration_root "CONFIGURATION_ROOT=\"/var/osquery/extensions/com/trailofbits/firewall\"")
  else()
    set(configuration_root "CONFIGURATION_ROOT=\"C:\\ProgramData\\osquery\\extensions\\com\\trailofbits\\firewall\"")
  endif()

  target_compile_definitions("${PROJECT_NAME}" PRIVATE "${configuration_root}")

  add_subdirectory(extutils)
  add_subdirectory(firewall)
  add_subdirectory(hostsfile)

  # The ADD_OSQUERY_EXTENSION has already used an old style target_link_libraries call, so
  # we can't use the PRIVATE/PUBLIC/INTERFACE dependency keywords
  target_link_libraries("${PROJECT_NAME}" firewall hostsfile)
endfunction()

set(ROOT_TEST_TARGET "${PROJECT_NAME}_tests")
add_custom_target("${ROOT_TEST_TARGET}")

function(AddTest test_name out_executable_target_name)
  set(target_name "fwctlTest_${test_name}")
  add_executable("${target_name}" EXCLUDE_FROM_ALL ${ARGN})

  # we have the guarantee that googletest is already present, thanks to osquery; link
  # to it so that we automatically import the include directories
  if(NOT TARGET gtest)
    message(FATAL_ERROR "Tests will not find gtest if you have built using the 'SKIP_TESTS=1' setting!")
  endif()

  target_link_libraries("${target_name}" PRIVATE gtest)

  if(UNIX AND NOT APPLE)
    set(command_prefix ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=/usr/local/osquery/lib)
  endif()

  add_custom_target("${target_name}_runner"
    COMMAND ${command_prefix} $<TARGET_FILE:${target_name}>
  )

  add_dependencies("${ROOT_TEST_TARGET}" "${target_name}_runner")

  # Return the executable target name to the caller
  set("${out_executable_target_name}" "${target_name}" PARENT_SCOPE)
endfunction()

main()

