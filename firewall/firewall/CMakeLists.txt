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
project(firewall)

function(main)
  if(DEFINED APPLE)
    set(PROJECT_SOURCEFILES
      macos/src/firewall.h
      macos/src/firewall.cpp
    )

    set(PROJECT_TESTFILES
      ${PROJECT_SOURCEFILES}

      macos/tests/main.cpp
      macos/tests/pf_firewall.cpp
    )

    set(PROJECT_TESTINCLUDEDIR
      "${CMAKE_CURRENT_SOURCE_DIR}/macos/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/macos/src"
    )

  elseif(DEFINED UNIX)
    set(PROJECT_SOURCEFILES
      linux/src/firewall.h
      linux/src/firewall.cpp
    )

    set(PROJECT_TESTFILES
      ${PROJECT_SOURCEFILES}

      linux/tests/main.cpp
      linux/tests/iptables_firewall.cpp
    )

    set(PROJECT_TESTINCLUDEDIR
      "${CMAKE_CURRENT_SOURCE_DIR}/linux/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/linux/src"
    )

  elseif(DEFINED WIN32)
    set(PROJECT_SOURCEFILES
      windows/src/firewall.h
      windows/src/firewall.cpp
    )

    set(PROJECT_TESTFILES
      ${PROJECT_SOURCEFILES}

      windows/tests/main.cpp
      windows/tests/windows_firewall.cpp
    )

    set(PROJECT_TESTINCLUDEDIR
      "${CMAKE_CURRENT_SOURCE_DIR}/windows/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/windows/src"
    )

  else()
    message(SEND_ERROR "Unsupported operating system")
  endif()

  set(PROJECT_PUBLICINCLUDEFOLDER "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND PROJECT_SOURCEFILES
    "${PROJECT_PUBLICINCLUDEFOLDER}/trailofbits/ifirewall.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${PROJECT_SOURCEFILES})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${PROJECT_PUBLICINCLUDEFOLDER}")
  target_link_libraries("${PROJECT_NAME}" PUBLIC extutils)

  AddTest("${PROJECT_NAME}" test_target_name ${PROJECT_TESTFILES})
  target_include_directories("${test_target_name}" PRIVATE
    "${PROJECT_PUBLICINCLUDEFOLDER}"
    "${PROJECT_TESTINCLUDEDIR}"
  )

  target_link_libraries("${test_target_name}" PRIVATE extutils boost_system-mt)
endfunction()

main()
