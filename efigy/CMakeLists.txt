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
project(efigy)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

function (main)
  set(PROJECT_SOURCEFILES
    src/utils.h
    src/utils.mm

    src/efigy.h
    src/efigy.cpp

    src/extension.h
    src/extension.cpp

    src/main.cpp
  )

  ADD_OSQUERY_EXTENSION("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" "-framework CoreFoundation" "-framework IOKit")

  find_package(curl REQUIRED)
  target_link_libraries("${PROJECT_NAME}" ${CURL_LIBRARIES})
  target_include_directories("${PROJECT_NAME}" PRIVATE ${CURL_INCLUDE_DIR})

  set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
  find_package(openssl REQUIRED)
  target_link_libraries("${PROJECT_NAME}" ${OPENSSL_LIBRARIES})
  target_include_directories("${PROJECT_NAME}" PRIVATE ${OPENSSL_INCLUDE_DIR})
endfunction ()

main()

