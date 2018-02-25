# Copyright (c) 2017 Trail of Bits, Inc.
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

  add_subdirectory(firewall)
  target_link_libraries("${PROJECT_NAME}" firewall)
endfunction()

main()

