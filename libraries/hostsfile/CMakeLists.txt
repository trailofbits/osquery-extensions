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

cmake_minimum_required(VERSION 3.10.0)
project(hostsfile)

function(main)
  set(project_source_files
    src/hostsfile.h
    src/hostsfile.cpp
  )

  set(project_public_include_folder "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND project_source_files
    "${project_public_include_folder}/trailofbits/ihostsfile.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${project_source_files})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${project_public_include_folder}")
  target_link_libraries("${PROJECT_NAME}" PUBLIC extutils)

  if(NOT DEFINED SKIP_TESTS)
    set(
      project_test_files

      tests/main.cpp

      src/hostsfile.h
      src/hostsfile.cpp
      tests/hostsfile.cpp
    )

    AddTest("${PROJECT_NAME}" test_target_name ${project_test_files})

    target_include_directories("${test_target_name}" PRIVATE
      "${project_public_include_folder}"
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )

    target_link_libraries("${test_target_name}" PRIVATE extutils)
  endif()
endfunction()

main()
