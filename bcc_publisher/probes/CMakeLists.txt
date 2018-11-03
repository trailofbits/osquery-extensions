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

cmake_minimum_required(VERSION 3.12)
project(bcc_publisher_probes)

function(importBccProbe probe_name)
  if("${probe_name}" STREQUAL "")
    message(FATAL_ERROR "No BCC probe name specified")
  endif()

  set(probe_path "${CMAKE_CURRENT_SOURCE_DIR}/probes/${probe_name}")
  if(NOT IS_DIRECTORY "${probe_path}")
    message(FATAL_ERROR "Invalid probe name; the following path does not exists: ${probe_path}")
  endif()

  file(GLOB probe_header_file_list
    LIST_DIRECTORIES false
    "${probe_path}/*.h"
  )

  file(GLOB probe_source_file_list
    LIST_DIRECTORIES false
    "${probe_path}/*.c"
  )

  list(APPEND probe_files ${probe_header_file_list} ${probe_source_file_list})

  set(probe_definition_file "${CMAKE_CURRENT_BINARY_DIR}/bcc_probe_${probe_name}.h")

  set(probeGenerator_sources "")
  foreach(probe_source_file ${probe_files})
    list(APPEND probeGenerator_sources "${probe_source_file}")
  endforeach()

  add_custom_command(
    OUTPUT "${probe_definition_file}"
    COMMAND "${CMAKE_COMMAND}"
    ARGS "-DprobeGenerator_probeVariableName=bcc_probe_${probe_name}" "-DprobeGenerator_sources=${probeGenerator_sources}" "-DprobeGenerator_destination=${probe_definition_file}" -P "${CMAKE_CURRENT_SOURCE_DIR}/probes/cmake/probe_generator.cmake"
    MAIN_DEPENDENCY ${probe_files}
    COMMENT "Generating probe: ${probe_name}: ${probe_definition_file}"
    VERBATIM
  )

  add_custom_target("bcc_probe_${probe_name}_generator" DEPENDS "${probe_definition_file}")

  add_library("bcc_probe_${probe_name}" INTERFACE)

  target_include_directories("bcc_probe_${probe_name}" INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/probes"
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  add_dependencies("bcc_probe_${probe_name}" "bcc_probe_${probe_name}_generator")
endfunction()
