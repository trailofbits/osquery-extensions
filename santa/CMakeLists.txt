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

cmake_minimum_required(VERSION 3.9.1)
project(santa)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

function(main)
  set(PROJECT_SOURCEFILES
    src/santa.h
    src/santa.cpp

    src/santaeventstable.h
    src/santaeventstable.cpp

    src/santarulestable.h
    src/santarulestable.cpp

    src/utils.h
    src/utils.cpp

    src/main.cpp
  )

  ADD_OSQUERY_EXTENSION("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" boost_iostreams-mt)
endfunction()

main()
