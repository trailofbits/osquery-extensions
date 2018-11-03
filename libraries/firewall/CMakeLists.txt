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
project(firewall)

function(main)
  if(DEFINED APPLE)
    set(project_source_files
      macos/src/firewall.h
      macos/src/firewall.cpp
    )

    set(project_test_files
      ${project_source_files}

      macos/tests/main.cpp
      macos/tests/pf_firewall.cpp
    )

    set(project_test_include_dirs
      "${CMAKE_CURRENT_SOURCE_DIR}/macos/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/macos/src"
    )

  elseif(DEFINED UNIX)
    set(project_source_files
      linux/src/firewall.h
      linux/src/firewall.cpp
    )

    set(project_test_files
      ${project_source_files}

      linux/tests/main.cpp
      linux/tests/iptables_firewall.cpp
    )

    set(project_test_include_dirs
      "${CMAKE_CURRENT_SOURCE_DIR}/linux/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/linux/src"
    )

  elseif(DEFINED WIN32)
    set(project_source_files
      windows/src/firewall.h
      windows/src/firewall.cpp
    )

    set(project_test_files
      ${project_source_files}

      windows/tests/main.cpp
      windows/tests/windows_firewall.cpp
    )

    set(project_test_include_dirs
      "${CMAKE_CURRENT_SOURCE_DIR}/windows/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/windows/src"
    )

  else()
    message(SEND_ERROR "Unsupported operating system")
  endif()

  set(project_public_include_folder "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND project_source_files
    "${project_public_include_folder}/trailofbits/ifirewall.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${project_source_files})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${project_public_include_folder}")
  target_link_libraries("${PROJECT_NAME}" PUBLIC extutils)

  if(NOT DEFINED SKIP_TESTS)
    AddTest("${PROJECT_NAME}" test_target_name ${project_test_files})
    target_include_directories("${test_target_name}" PRIVATE
      "${project_public_include_folder}"
      "${project_test_include_dirs}"
    )

    target_link_libraries("${test_target_name}" PRIVATE extutils)

    if(UNIX)
      target_link_libraries("${test_target_name}" PRIVATE boost_system-mt boost_filesystem-mt)
    else()
      target_link_libraries("${test_target_name}" PRIVATE libboost_system-mt-s libboost_filesystem-mt-s)
    endif()
  endif()
endfunction()

main()
