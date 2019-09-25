/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#if OSQUERY_VERSION_NUMBER <= 4000
#include <osquery/status.h>
#else
#include <osquery/flags.h>
#endif

#include <memory>
#include <vector>

#include <pcap.h>

namespace trailofbits {
/// This is the std::unique_ptr deleter used when wrapping pcap handles
void pcapRefDeleter(pcap_t* handle);

/// A pcap handle reference
using PcapRef = std::unique_ptr<pcap_t, void (*)(pcap_t*)>;

/// Helper macro used to declare an empty ref for pcap handles
#define DeclarePcapRef(x)                                                      \
  PcapRef x {                                                                  \
    nullptr, pcapRefDeleter                                                    \
  }

/// A network address with the associated netmask (either IPV4 or IPV6)
struct NetworkAddress final {
  std::string address;
  std::string netmask;
};

/// Describes the properties for a network interface
struct NetworkDeviceInformation final {
  std::string name;
  std::string description;

  std::vector<NetworkAddress> ipv4_address_list;
  std::vector<NetworkAddress> ipv6_address_list;

  bpf_u_int32 flags;
};

/// Creates a new pcap handle
osquery::Status createPcap(PcapRef& ref,
                           const std::string& device_name,
                           int capture_buffer_size,
                           int packet_capture_timeout,
                           bool promiscuous_mode);

/// Returns the device information for the specified network interface
osquery::Status getNetworkDeviceInformation(NetworkDeviceInformation& dev_info,
                                            const std::string& device_name);

/// Performs a poll() on the given pcap handle, waiting for new packets
osquery::Status waitForNewPackets(bool& timed_out,
                                  PcapRef& ref,
                                  std::size_t msecs);
} // namespace trailofbits
