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
    set(configuration_root "CONFIGURATION_ROOT=\"/var/osquery/extensions/com/trailofbits/fwctl\"")
  else()
    set(configuration_root "CONFIGURATION_ROOT=\"C:\\\\ProgramData\\\\osquery\\\\extensions\\\\com\\\\trailofbits\\\\fwctl\"")
  endif()

  target_compile_definitions("${PROJECT_NAME}" PRIVATE "${configuration_root}")

  add_subdirectory(extutils)
  add_subdirectory(firewall)
  add_subdirectory(hostsfile)

  # The ADD_OSQUERY_EXTENSION has already used an old style target_link_libraries call, so
  # we can't use the PRIVATE/PUBLIC/INTERFACE dependency keywords
  target_link_libraries("${PROJECT_NAME}" firewall hostsfile)

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  find_package(Boost REQUIRED COMPONENTS serialization REQUIRED)
  target_include_directories("${PROJECT_NAME}" PRIVATE ${Boost_INCLUDE_DIRS})
  target_link_libraries("${PROJECT_NAME}" ${Boost_LIBRARIES})

  set(
    PROJECT_TESTFILES

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

  AddTest("tables" test_target_name ${PROJECT_TESTFILES})
  target_include_directories("${test_target_name}" PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  target_link_libraries("${test_target_name}" PRIVATE
    glog gflags thrift boost_system-mt boost_thread-mt boost_filesystem-mt boost_context-mt
    firewall hostsfile
  )

  if(UNIX)
    target_link_libraries("${test_target_name}" PRIVATE "${CMAKE_BINARY_DIR}/osquery/libosquery.a")

    if(NOT APPLE)
      target_link_libraries("${test_target_name}" PRIVATE rt)
    endif()
  else()
    target_link_libraries("${test_target_name}" PRIVATE "${CMAKE_BINARY_DIR}/osquery/osquery.lib")
  endif()
endfunction()

set(ROOT_TEST_TARGET "${PROJECT_NAME}_tests")
add_custom_target("${ROOT_TEST_TARGET}")

function(AddTest test_name out_executable_target_name)
  set(target_name "fwctlTest_${test_name}")
  add_executable("${target_name}" EXCLUDE_FROM_ALL ${ARGN})

  message(STATUS "Generating test: ${target_name}")

  # we have the guarantee that googletest is already present, thanks to osquery; link
  # to it so that we automatically import the include directories
  if(NOT TARGET gtest)
    message(FATAL_ERROR "Tests will not find gtest if you have built using the 'SKIP_TESTS=1' setting!")
  endif()

  target_link_libraries("${target_name}" PRIVATE gtest)

  if(UNIX)
    if(APPLE)
      target_compile_definitions("${target_name}" PRIVATE APPLE)
    else()
      set(command_prefix ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=/usr/local/osquery/lib)
      target_compile_definitions("${target_name}" PRIVATE LINUX)
    endif()
  else()
    target_compile_definitions("${target_name}" PRIVATE WINDOWS)
  endif()

  add_custom_target("${target_name}_runner"
    COMMAND ${command_prefix} $<TARGET_FILE:${target_name}>
    COMMENT "Running test: ${target_name}"
  )

  add_dependencies("${ROOT_TEST_TARGET}" "${target_name}_runner")

  # Return the executable target name to the caller
  set("${out_executable_target_name}" "${target_name}" PARENT_SCOPE)
endfunction()

main()

