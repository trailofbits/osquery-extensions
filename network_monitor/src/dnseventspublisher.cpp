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

#include "dnseventspublisher.h"
#include "pcap_utils.h"

#include <iostream>
#include <variant>

namespace trailofbits {
namespace {
const int kSnapshotLength = 4096;
const int kPacketBufferTimeout = 1000;

const std::string kFilterRules = "port 53 and (tcp or udp)";
} // namespace

/// Private class data
struct DNSEventsPublisher::PrivateData final {
  // Contains device information such as IP addresses and netmasks
  NetworkDeviceInformation device_information;

  // The pcap handle
  DeclarePcapRef(pcap);

  // The eBPF program used to filter the network traffic
  struct bpf_program ebpf_filter_program {};
};

DNSEventsPublisher::DNSEventsPublisher() : d(new PrivateData) {}

osquery::Status DNSEventsPublisher::create(IEventPublisherRef& publisher) {
  try {
    auto ptr = new DNSEventsPublisher();
    publisher.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status DNSEventsPublisher::initialize() noexcept {
  std::cout << "Initializing NetworkEventPublisher\n";
  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::release() noexcept {
  std::cout << "Releasing NetworkEventPublisher\n";
  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::configure(
    const json11::Json& configuration) noexcept {
  static_cast<void>(kSnapshotLength);
  static_cast<void>(kPacketBufferTimeout);
  static_cast<void>(configuration);
  std::cout << "Configuring NetworkEventPublisher\n";
  return osquery::Status(0);

  /*static const std::string device_name = "enp7s0";

  auto status =
      createPcap(d->pcap, device_name, kSnapshotLength, kPacketBufferTimeout);
  if (!status.ok()) {
    return status;
  }

  auto link_header_type = pcap_datalink(d->pcap.get());
  if (link_header_type == PCAP_ERROR_NOT_ACTIVATED) {
    return osquery::Status(1, "Failed to acquire the link-layer header type");
  }

  bool valid_link_header_type = false;
  switch (link_header_type) {
  case DLT_IPV4:
  case DLT_IPV6:
  case DLT_EN10MB:
    valid_link_header_type = true;
    break;

  default:
    break;
  }

  if (!valid_link_header_type) {
    return osquery::Status(1, "Invalid link-layer header type");
  }

  status = getNetworkDeviceInformation(d->device_information, device_name);
  if (!status.ok()) {
    return status;
  }

  if (pcap_compile(d->pcap.get(),
                   &d->ebpf_filter_program,
                   kFilterRules.c_str(),
                   1,
                   PCAP_NETMASK_UNKNOWN) != 0) {
    auto error_message = std::string("Failed to compile the eBPF filter: ") +
                         pcap_geterr(d->pcap.get());
    return osquery::Status(1, error_message);
  }

  if (pcap_setfilter(d->pcap.get(), &d->ebpf_filter_program) != 0) {
    auto error_message =
        std::string("Failed to enable the eBPF filter program: ") +
        pcap_geterr(d->pcap.get());
    return osquery::Status(1, error_message);
  }

  return osquery::Status(0);*/
}

osquery::Status DNSEventsPublisher::run() noexcept {
  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  emitEvents(event_context);
  return osquery::Status(0);
}
} // namespace trailofbits
