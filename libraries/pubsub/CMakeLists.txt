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
project(pubsub)

function(pubsubMain)
  #
  # Source files
  #

  set(public_include_folder "${CMAKE_CURRENT_SOURCE_DIR}/include")

  set(source_files
    src/publisherregistry.cpp
    src/subscriberregistry.cpp

    src/publisherscheduler.cpp
  )

  set(public_include_files
    "${public_include_folder}/ieventpublisher.h"
    "${public_include_folder}/ieventsubscriber.h"

    "${public_include_folder}/baseeventpublisher.h"
    "${public_include_folder}/baseeventsubscriber.h"

    "${public_include_folder}/publisherregistry.h"
    "${public_include_folder}/subscriberregistry.h"

    "${public_include_folder}/publisherscheduler.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files} ${public_include_files})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${public_include_folder}")

  #
  # Compilation flags
  #

  set(compile_options
    -Werror -Wconversion -Wall -pedantic -Wunused
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    list(APPEND compile_options -g3)
  endif()

  target_compile_options("${PROJECT_NAME}" PRIVATE ${compile_options})

  #
  # Dependencies
  #

  #target_link_libraries("${PROJECT_NAME}" PUBLIC )

  #find_package(Threads)
  #list(APPEND libraries ${CMAKE_THREAD_LIBS_INIT})

  #find_package(Boost REQUIRED COMPONENTS thread)
  #list(APPEND libraries ${Boost_LIBRARIES})
  #list(APPEND include_dirs ${Boost_INCLUDE_DIRS})

  #target_include_directories("${PROJECT_NAME}" PUBLIC ${include_dirs})
  #target_link_libraries("${PROJECT_NAME}" PUBLIC ${libraries})
endfunction()

pubsubMain()
