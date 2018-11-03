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

function(probeGenerator)
  if("${probeGenerator_probeVariableName}" STREQUAL "")
    message(FATAL_ERROR "The probe variable name parameter has not been defined: probeGenerator_probeVariableName")
  endif()

  if("${probeGenerator_sources}" STREQUAL "")
    message(FATAL_ERROR "The sources file parameter has not been defined: probeGenerator_sources")
  endif()

  if("${probeGenerator_destination}" STREQUAL "")
    message(FATAL_ERROR "The destination file parameter has not been defined: probeGenerator_destination")
  endif()

  execute_process(
    COMMAND sh -c "echo -n > '${probeGenerator_destination}'"
    COMMAND sh -c "echo 'static const std::string ${probeGenerator_probeVariableName} = R\"PROBE_SOURCE(' >> '${probeGenerator_destination}'"
  )

  foreach(probe_source_file ${probeGenerator_sources})
    execute_process(
      COMMAND sh -c "cat '${probe_source_file}' >> '${probeGenerator_destination}'"
    )
  endforeach()

  execute_process(
    COMMAND sh -c "echo ')PROBE_SOURCE\";' >> '${probeGenerator_destination}'"
  )
endfunction()

probeGenerator()
