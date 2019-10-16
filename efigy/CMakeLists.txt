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
project(efigy)

function(main)
  set(project_libraries
    "-framework CoreFoundation"
    "-framework IOKit"
  )

  find_package(curl REQUIRED)
  list(APPEND project_libraries
    ${CURL_LIBRARIES}
  )

  list(APPEND project_include_folders
    ${CURL_INCLUDE_DIR}
    ${TOB_EXTENSIONS_ROOT}
  )

  # set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
  # find_package(openssl REQUIRED)
  # list(APPEND project_libraries
  #   ${OPENSSL_LIBRARIES}
  # )

  list(APPEND project_include_folders
    ${OPENSSL_INCLUDE_DIR}
  )

  set(source_files
    src/utils.h
    src/utils.mm

    src/efigy.h
    src/efigy.cpp

    src/efigytable.h
    src/efigytable.cpp
  )

  addOsqueryExtensionEx("EFIgyTablePlugin" "table" "EFIgy"
    SOURCES ${source_files}
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src" ${project_include_folders}
    MAININCLUDES efigytable.h
    LIBRARIES ${project_libraries}
  )
endfunction()

main()

