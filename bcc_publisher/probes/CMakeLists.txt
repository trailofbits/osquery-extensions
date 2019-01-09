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

  list(APPEND probe_file_list
    "${CMAKE_CURRENT_SOURCE_DIR}/probes/common/definitions.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/probes/common/utilities.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/probes/common/helpers.h"

    ${probe_header_file_list}
    ${probe_source_file_list}
  )

  set(probe_definition_folder "${CMAKE_CURRENT_BINARY_DIR}/probes")
  set(probe_definition_file "${probe_definition_folder}/${probe_name}.h")

  foreach(probe_file ${probe_header_file_list})
    list(APPEND header_command_list
      COMMAND sh -c "cat \"${probe_file}\" >> \"${probe_definition_file}\""
      COMMAND sh -c "echo \"\\n\\n\" >> \"${probe_definition_file}\""
    )
  endforeach()

  foreach(probe_file ${probe_file_list})
    list(APPEND body_command_list
      COMMAND sh -c "cat \"${probe_file}\" >> \"${probe_definition_file}\""
      COMMAND sh -c "echo \"\\n\\n\" >> \"${probe_definition_file}\""
    )
  endforeach()

  if(NOT TARGET probe_definition_folder_generator)
    add_custom_command(
      OUTPUT "${probe_definition_folder}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${probe_definition_folder}"
      VERBATIM
    )

    add_custom_target(probe_definition_folder_generator DEPENDS "${probe_definition_folder}")
  endif()

  add_custom_command(
    OUTPUT "${probe_definition_file}"

    COMMAND sh -c "echo -n > \"${probe_definition_file}\""
    ${header_command_list}
    COMMAND sh -c "echo '#include <string>\\n\\nstatic const std::string kBccProbe_${probe_name} = R\"PROBE_SOURCE(' >> '${probe_definition_file}'"
    ${body_command_list}
    COMMAND sh -c "echo ')PROBE_SOURCE\";' >> '${probe_definition_file}'"

    DEPENDS probe_definition_folder_generator ${probe_file_list}
    COMMENT "Generating probe: ${probe_name}"
    WORKING_DIRECTORY "${probe_definition_folder}"
    VERBATIM
  )

  add_custom_target("bcc_probe_generator_${probe_name}" DEPENDS "${probe_definition_file}")

  add_library("bcc_probe_${probe_name}" INTERFACE)
  target_include_directories("bcc_probe_${probe_name}" INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  add_dependencies("bcc_probe_${probe_name}" "bcc_probe_generator_${probe_name}")
endfunction()
