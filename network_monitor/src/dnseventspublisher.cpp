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

#include <variant>

namespace trailofbits {
namespace {
/// Capture buffer
const int kSnapshotLength = 4096;

/// Capcture timeout, used when waiting for the next packet
const int kPacketBufferTimeout = 1000;

/// The eBPF program used to filter the packets
const std::string kFilterRules = "port 53 and (tcp or udp)";

/// A reference to a TCP reassembler object
using TcpReassemblyRef = std::unique_ptr<pcpp::TcpReassembly>;

/// A vector of bytes
using ByteVector = std::vector<std::uint8_t>;

/// Used to keep track of a TCP conversation between two hosts
struct TcpConversation final {
  ByteVector sent_data;
  ByteVector received_data;
};

/// The identifier is used by the TCP reassembler to uniquely identify a
/// connection
using TcpConversationId = std::uint32_t;

/// A map containing TCP conversations
using TcpConversationMap =
    std::unordered_map<TcpConversationId, TcpConversation>;
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
  pcpp::LinkLayerType link_type;

  // This class instance is used to reassemble TCP packets
  TcpReassemblyRef tcp_reassembler;

  // Completed TCP conversations
  TcpConversationMap completed_tcp_conversation_map;

  // Pending TCP conversations
  TcpConversationMap pending_tcp_conversation_map;
};

namespace {
TcpConversation& getPendingTcpConversation(
    std::unique_ptr<DNSEventsPublisher::PrivateData>& d,
    int side,
    TcpConversationId identifier) {
  auto it = d->pending_tcp_conversation_map.find(identifier);
  if (it == d->pending_tcp_conversation_map.end()) {
    auto insert_res = d->pending_tcp_conversation_map.insert({identifier, {}});
    it = insert_res.first;
  }

  auto& conversation = it->second;
  return conversation;
}
} // namespace

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

  auto pcap_link_type = pcap_datalink(d->pcap.get());
  if (pcap_link_type == PCAP_ERROR_NOT_ACTIVATED) {
    return osquery::Status(1, "Failed to acquire the link-layer header type");
  }

  bool valid_link_header_type = false;
  switch (pcap_link_type) {
  case DLT_IPV4: {
    d->link_type = pcpp::LINKTYPE_IPV4;
    valid_link_header_type = true;
    break;
  }

  case DLT_IPV6: {
    d->link_type = pcpp::LINKTYPE_IPV6;
    valid_link_header_type = true;
    break;
  }

  case DLT_EN10MB: {
    d->link_type = pcpp::LINKTYPE_ETHERNET;
    valid_link_header_type = true;
    break;
  }

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

  static auto L_onTcpMessageReady =
      [](int side, pcpp::TcpStreamData tcp_data, void* user_cookie) -> void {
    auto& publisher = *reinterpret_cast<DNSEventsPublisher*>(user_cookie);
    publisher.onTcpMessageReady(side, tcp_data);
  };

  static auto L_onTcpConnectionStart = [](pcpp::ConnectionData connection_data,
                                          void* user_cookie) -> void {
    auto& publisher = *reinterpret_cast<DNSEventsPublisher*>(user_cookie);
    publisher.onTcpConnectionStart(connection_data);
  };

  static auto L_onTcpConnectionEnd =
      [](pcpp::ConnectionData connection_data,
         pcpp::TcpReassembly::ConnectionEndReason reason,
         void* user_cookie) -> void {
    auto& publisher = *reinterpret_cast<DNSEventsPublisher*>(user_cookie);
    publisher.onTcpConnectionEnd(connection_data, reason);
  };

  d->tcp_reassembler = std::make_unique<pcpp::TcpReassembly>(
      L_onTcpMessageReady, this, L_onTcpConnectionStart, L_onTcpConnectionEnd);

  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::run() noexcept {
  auto start_time = std::chrono::system_clock::now();

  std::vector<ByteVector> udp_packet_list;

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

    pcpp::RawPacket raw_packet(packet_data_buffer,
                               packet_header->len,
                               packet_header->ts,
                               false,
                               d->link_type);

    pcpp::Packet packet(&raw_packet);
    if (packet.isPacketOfType(pcpp::UDP)) {
      ByteVector packet_data(packet_header->len);
      packet_data.assign(packet_data_buffer,
                         packet_data_buffer + packet_header->len);

      udp_packet_list.push_back(std::move(packet_data));

    } else {
      d->tcp_reassembler->reassemblePacket(&raw_packet);
    }
  }

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  for (const auto& udp_packet : udp_packet_list) {
    LOG(ERROR) << "UDP datagram: " << udp_packet.size();
  }

  for (const auto& p : d->completed_tcp_conversation_map) {
    const auto& conversation_id = p.first;
    const auto& tcp_conversation = p.second;

    LOG(ERROR) << "Conversation id: " << conversation_id
               << ". Sent: " << tcp_conversation.sent_data.size()
               << ". Received: " << tcp_conversation.received_data.size();
  }

  d->completed_tcp_conversation_map.clear();

  emitEvents(event_context);
  return osquery::Status(0);
}

void DNSEventsPublisher::onTcpMessageReady(int side,
                                           pcpp::TcpStreamData tcp_data) {
  auto connection_data = tcp_data.getConnectionData();
  auto conversation_id = connection_data.flowKey;

  auto& conversation = getPendingTcpConversation(d, side, conversation_id);
  auto& stream_buffer =
      (side == 0) ? conversation.sent_data : conversation.received_data;

  auto data_length = static_cast<std::size_t>(tcp_data.getDataLength());
  const auto data_begin = tcp_data.getData();
  const auto data_end = data_begin + data_length;

  stream_buffer.reserve(stream_buffer.size() + data_length);
  stream_buffer.insert(stream_buffer.end(), data_begin, data_end);
}

void DNSEventsPublisher::onTcpConnectionStart(
    pcpp::ConnectionData connection_data) {
  static_cast<void>(connection_data);
}

void DNSEventsPublisher::onTcpConnectionEnd(
    pcpp::ConnectionData connection_data,
    pcpp::TcpReassembly::ConnectionEndReason reason) {
  auto conversation_id = connection_data.flowKey;

  auto it = d->pending_tcp_conversation_map.find(conversation_id);
  if (it == d->pending_tcp_conversation_map.end()) {
    return;
  }

  auto& conversation = it->second;
  d->completed_tcp_conversation_map.insert(
      {conversation_id, std::move(conversation)});

  d->pending_tcp_conversation_map.erase(it);
}
} // namespace trailofbits
