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
project(network_monitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(main)
  #
  # Source files
  #

  set(source_files
    src/main.cpp

    src/networkeventpublisher.h
    src/networkeventpublisher.cpp

    src/networkeventsubscriber.h
    src/networkeventsubscriber.cpp

    src/pcap_utils.h
    src/pcap_utils.cpp
  )

  add_osquery_extension("${PROJECT_NAME}" ${source_files})

  #
  # Dependencies
  #

  # Import our pubsub framework
  list(APPEND libraries pubsub)

  # Attempt to import libpcap from the opt_dependencies folder
  ImportDependency("pcap")
  list(APPEND libraries pcap)

  target_link_libraries("${PROJECT_NAME}" ${libraries})
endfunction()

main()
