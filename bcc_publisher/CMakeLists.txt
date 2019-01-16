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
project(bcc_publisher)

function(bccPublisherMain)
  ImportDependency("bcc")

  add_subdirectory(probes)

  set(probe_list
    "create_mknod_events"
    "dup_close_events"
    "exec_events"
    "fork_events"
    "open_events"
    "socket_fd_events"
  )

  foreach(probe_name ${probe_list})
    importBccProbe("${probe_name}")
    list(APPEND probe_target_list "bcc_probe_${probe_name}")
  endforeach()

  set(source_files
    src/main.cpp

    src/bccprocesseventspublisher.h
    src/bccprocesseventspublisher.cpp

    src/bccprocesseventsprogramtypes.h
    src/bccprocesseventsprogram.h
    src/bccprocesseventsprogram.cpp

    src/bccprocessevents.h
    src/bccprocessevents.cpp

    src/bccprocesseventsservice.h
    src/bccprocesseventsservice.cpp

    src/globals.h
    src/globals.cpp

    src/dockertracker.h
    src/dockertracker.cpp
  )

  add_osquery_extension("${PROJECT_NAME}" ${source_files})
  target_link_libraries("${PROJECT_NAME}"
    pubsub
    bcc
    ${probe_target_list}
  )

  # We have to disable some warnings for BCC to work correctly
  # (since we are using -Werror0)
  target_compile_options("${PROJECT_NAME}" PRIVATE
    -Wno-shadow
    -Wno-shadow-field-in-constructor
    -Wno-gnu-anonymous-struct
    -Wno-nested-anon-types
    -Wno-reorder
    -Wno-unused-result
    -Wno-non-virtual-dtor
    -g0
  )
endfunction()

bccPublisherMain()
