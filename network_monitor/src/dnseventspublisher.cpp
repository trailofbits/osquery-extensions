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

  // Link type
  int link_type{0};
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
  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::release() noexcept {
  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::configure(
    const json11::Json& configuration) noexcept {
  if (!configuration.is_object()) {
    return osquery::Status(1, "Invalid configuration");
  }

  const auto& dns_event_configuration = configuration["dns_events"];
  if (dns_event_configuration == json11::Json()) {
    return osquery::Status(0,
                           "The 'dns_events' configuration section is missing");
  }

  const auto& interface_name_obj = dns_event_configuration["interface"];
  if (interface_name_obj == json11::Json()) {
    return osquery::Status(
        0, "The 'interface' value is missing from the 'dns_events' section");
  }

  auto interface_name = interface_name_obj.string_value();
  auto status = createPcap(
      d->pcap, interface_name, kSnapshotLength, kPacketBufferTimeout);

  if (!status.ok()) {
    return status;
  }

  d->link_type = pcap_datalink(d->pcap.get());
  if (d->link_type == PCAP_ERROR_NOT_ACTIVATED) {
    return osquery::Status(1, "Failed to acquire the link-layer header type");
  }

  bool valid_link_header_type = false;
  switch (d->link_type) {
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

  status = getNetworkDeviceInformation(d->device_information, interface_name);
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

  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::run() noexcept {
  auto start_time = std::chrono::system_clock::now();

  PacketList packet_list;

  while (true) {
    auto current_time = std::chrono::system_clock::now();
    auto elapsed_time = current_time - start_time;

    if (elapsed_time > std::chrono::seconds(5U)) {
      break;
    }

    pcap_pkthdr* packet_header = nullptr;
    const std::uint8_t* packet_data_buffer = nullptr;
    auto capture_error =
        pcap_next_ex(d->pcap.get(), &packet_header, &packet_data_buffer);

    if (capture_error == 0) {
      break;

    } else if (capture_error == -1) {
      auto error_message = std::string("Failed to capture the next packet: ") +
                           pcap_geterr(d->pcap.get());

      return osquery::Status(1, error_message);
    }

    PacketData packet_data;
    packet_data.assign(packet_data_buffer,
                       packet_data_buffer + packet_header->len);
    packet_list.insert({packet_header->ts, std::move(packet_data)});
  }

  if (packet_list.empty()) {
    return osquery::Status(0);
  }

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  event_context->link_type = d->link_type;
  event_context->packet_list = std::move(packet_list);
  packet_list.clear();

  emitEvents(event_context);
  return osquery::Status(0);
}
} // namespace trailofbits
