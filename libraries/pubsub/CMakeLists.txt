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
    src/servicemanager.cpp

    src/eventbufferlibrary.cpp
    src/publisherscheduler.cpp
    src/configurationfile.cpp
  )

  set(public_include_files
    "${public_include_folder}/pubsub/servicemanager.h"

    "${public_include_folder}/pubsub/ieventpublisher.h"
    "${public_include_folder}/pubsub/ieventsubscriber.h"

    "${public_include_folder}/pubsub/baseeventpublisher.h"
    "${public_include_folder}/pubsub/baseeventsubscriber.h"

    "${public_include_folder}/pubsub/publisherregistry.h"
    "${public_include_folder}/pubsub/subscriberregistry.h"

    "${public_include_folder}/pubsub/eventbufferlibrary.h"
    "${public_include_folder}/pubsub/publisherscheduler.h"
    "${public_include_folder}/pubsub/configurationfile.h"
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

  # list(APPEND libraries boost_thread-mt)

  find_package(Threads)
  list(APPEND libraries ${CMAKE_THREAD_LIBS_INIT})

  ImportDependency("json11")
  list(APPEND libraries json11)

  target_link_libraries("${PROJECT_NAME}" PUBLIC
	${libraries}
	osquery_sdk_pluginsdk
	thirdparty_boost
  )

endfunction()

pubsubMain()
