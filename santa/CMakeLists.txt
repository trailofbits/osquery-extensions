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
project(santa)

function(main)
  set(project_common_source_files
    src/santa.h
    src/santa.cpp

    src/utils.h
    src/utils.cpp
  )

  set(project_libraries boost_iostreams-mt)

  add_osquery_extension_ex("SantaRulesTablePlugin" "table" "santa_rules"
    SOURCES ${project_common_source_files} src/santarulestable.h src/santarulestable.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES santarulestable.h
    LIBRARIES ${project_libraries}
  )

  add_osquery_extension_ex("SantaAllowedDecisionsTablePlugin" "table" "santa_allowed"
    SOURCES ${project_common_source_files} src/santadecisionstable.h src/santadecisionstable.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES santadecisionstable.h
    LIBRARIES ${project_libraries}
  )

  add_osquery_extension_ex("SantaDeniedDecisionsTablePlugin" "table" "santa_denied"
    SOURCES ${project_common_source_files} src/santadecisionstable.h src/santadecisionstable.cpp
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES santadecisionstable.h
    LIBRARIES ${project_libraries}
  )
endfunction()

main()
