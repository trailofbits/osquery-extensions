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
project(ebpf)

function(ebpfMain)
  set(source_files
    src/ebpfeventsource.h
    src/ebpfeventsource.cpp

    src/ebpfprobe.h
    src/ebpfprobe.cpp

    src/main.cpp

    src/bcc_probe_generator.h
    src/bcc_probe_generator.cpp

    src/ebpfprobepollservice.h
    src/ebpfprobepollservice.cpp

    src/probereaderservice.h
    src/probereaderservice.cpp

    src/processeventspublisher.h
    src/processeventspublisher.cpp

    src/processeventssubscriber.h
    src/processeventssubscriber.cpp
  )

  add_osquery_extension("${PROJECT_NAME}" ${source_files})
  target_link_libraries("${PROJECT_NAME}" pubsub bcc_probe_api bcc_kprobe_header)

  ImportDependency("bcc")
  target_link_libraries("${PROJECT_NAME}" bcc)

  target_include_directories("${PROJECT_NAME}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

  add_subdirectory("probes")
  generateBccProbe("kprobe_group")
  target_link_libraries("${PROJECT_NAME}" bcc_probe_kprobe_group)
endfunction()

ebpfMain()
