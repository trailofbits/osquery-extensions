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

function(probesMain)
  generateBccProbeApiTarget()
endfunction()

function(generateBccProbeApiTarget)
  set(output_file "${CMAKE_CURRENT_BINARY_DIR}/bcc_probe_api.h")

  set(definitions_file "${CMAKE_CURRENT_SOURCE_DIR}/common/defs.h")
  set(api_file "${CMAKE_CURRENT_SOURCE_DIR}/common/api.h")

  add_custom_command(
    OUTPUT "${output_file}"
    DEPENDS "${definitions_file}" "${api_file}"

    COMMAND "${CMAKE_COMMAND}" -E echo "static const std::string kBccProbeAPI = R\"BCC_PROBE_API(" > "${output_file}"

    COMMAND "/usr/bin/env" bash -c "cat \"${definitions_file}\"" >> "${output_file}"
    COMMAND "${CMAKE_COMMAND}" -E echo >> "${output_file}"

    COMMAND "/usr/bin/env" bash -c "cat \"${api_file}\"" >> "${output_file}"
    COMMAND "${CMAKE_COMMAND}" -E echo >> "${output_file}"

    COMMAND "${CMAKE_COMMAND}" -E echo ")BCC_PROBE_API\";" >> "${output_file}"

    VERBATIM
  )

  add_custom_target(
    bcc_probe_api_generator
    DEPENDS "${output_file}"
  )

  add_library(bcc_probe_api INTERFACE)
  add_dependencies(bcc_probe_api bcc_probe_api_generator)
  target_include_directories(bcc_probe_api INTERFACE "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

function(generateProbe)
endfunction()

probesMain()
