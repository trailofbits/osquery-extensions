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

set(ROOT_TEST_TARGET "trailofbits_extensions_tests")
add_custom_target("${ROOT_TEST_TARGET}")

set(ENV{OSQUERY_EXTENSION_GROUP_NAME} "trailofbits_osquery_extensions")
set(ENV{OSQUERY_EXTENSION_GROUP_VERSION} "1.0")

function(main)
  message(STATUS "================================")
  message(STATUS "Trail of Bits osquery extensions")
  message(STATUS "Version: $ENV{OSQUERY_EXTENSION_GROUP_VERSION}")
  message(STATUS "================================")

  ImportLibraries()
  ImportExtensions()

  message(STATUS "================================")
endfunction()

function(ImportLibraries)
  message("Importing libraries from '${CMAKE_CURRENT_SOURCE_DIR}/libraries/${library}'")

  file(GLOB library_list RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/libraries" "${CMAKE_CURRENT_SOURCE_DIR}/libraries/*")
  foreach(library ${library_list})
    set(full_library_path "${CMAKE_CURRENT_SOURCE_DIR}/libraries/${library}")
    if(NOT IS_DIRECTORY "${full_library_path}")
      continue()
    endif()

    IsFolderEnabled("libraries/${library}")
    if(NOT "${IsFolderEnabled_OUTPUT}")
      continue()
    endif()

    message(" > ${library}")
    add_subdirectory("${full_library_path}" "libraries/${library}")
  endforeach()
endfunction()

function(ImportExtensions)
  message("Importing extensions from '${CMAKE_CURRENT_SOURCE_DIR}'")

  file(GLOB extension_list RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/*")
  foreach(extension ${extension_list})
    if("${extension}" STREQUAL ".vscode")
      continue()
    endif()

    set(full_extension_path "${CMAKE_CURRENT_SOURCE_DIR}/${extension}")
    if(NOT IS_DIRECTORY "${full_extension_path}")
      continue()
    endif()

    if("${extension}" STREQUAL "libraries" OR "${extension}" STREQUAL ".git")
      continue()
    endif()

    IsFolderEnabled("${extension}")
    if(NOT "${IsFolderEnabled_OUTPUT}")
      continue()
    endif()

    message(" > ${extension}")
    add_subdirectory("${extension}" "extensions/${extension}")
  endforeach()
endfunction()

function(IsFolderEnabled relative_path)
  set(platforms_file_path "${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/.platforms")

  if(NOT EXISTS "${platforms_file_path}")
    message(" ! Missing '.platforms` file: ${relative_path}. Skipping...")

    set(IsFolderEnabled_OUTPUT false PARENT_SCOPE)
    return()
  endif()

  file(READ "${platforms_file_path}" supported_platforms)
  if(WINDOWS AND "${supported_platforms}" MATCHES "WINDOWS")
    set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  elseif(APPLE AND "${supported_platforms}" MATCHES "APPLE")
    set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  elseif(LINUX AND "${supported_platforms}" MATCHES "LINUX")
    set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  else()
    set(IsFolderEnabled_OUTPUT false PARENT_SCOPE)
  endif()
endfunction()

function(AddTest test_name out_executable_target_name)
  set(target_name "tobExtTests_${test_name}")
  add_executable("${target_name}" EXCLUDE_FROM_ALL ${ARGN})

  message("   ${target_name}")

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
