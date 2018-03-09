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
project(santa)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

function (main)
  set(PROJECT_SOURCEFILES
    src/santa.h
    src/santa.cpp

    src/extension.h
    src/extension.cpp

    src/main.cpp
  )

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  find_package(Boost REQUIRED COMPONENTS iostreams)

  include_directories(${Boost_INCLUDE_DIRS})

  ADD_OSQUERY_EXTENSION("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" ${Boost_LIBRARIES})

endfunction ()

main()

