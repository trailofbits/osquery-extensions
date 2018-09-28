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

function(main)
  #
  # Source files
  #

  set(source_files
    src/main.cpp

    src/dnseventspublisher.h
    src/dnseventspublisher.cpp

    src/dnseventssubscriber.h
    src/dnseventssubscriber.cpp

    src/pcap_utils.h
    src/pcap_utils.cpp
  )

  add_osquery_extension("${PROJECT_NAME}" ${source_files})

  #
  # Dependencies
  #

  # Reference our pubsub framework
  list(APPEND libraries pubsub)

  # Import libpcap
  ImportDependency("pcap")
  list(APPEND libraries pcap)

  target_link_libraries("${PROJECT_NAME}" ${libraries})
endfunction()

main()
