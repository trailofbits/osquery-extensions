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

#include <IPv4Layer.h>
#include <IPv6Layer.h>

namespace trailofbits {
namespace {
/// Capture buffer size
const int kCaptureBufferSize = 4096;

/// Capture timeout, used when waiting for the next packet to arrive
const int kPacketCaptureTimeout = 5000;

/// The eBPF program used to filter the packets
const std::string kFilterRules = "port 53 and (tcp or udp)";

/// A reference to a TCP reassembler object
using TcpReassemblyRef = std::unique_ptr<pcpp::TcpReassembly>;

/// A vector of bytes
using ByteVector = std::vector<std::uint8_t>;

/// Used to keep track of a TCP conversation between two hosts
struct TcpConversation final {
  /// Contains data about the connection (such as ip addresses and ports)
  pcpp::ConnectionData connection_data;

  /// Data received
  ByteVector received_data;

  /// Data sent
  ByteVector sent_data;

  /// When the conversation was started
  timeval event_time{};
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
    TcpConversationId identifier) {
  auto it = d->pending_tcp_conversation_map.find(identifier);
  if (it == d->pending_tcp_conversation_map.end()) {
    auto insert_res = d->pending_tcp_conversation_map.insert({identifier, {}});
    it = insert_res.first;
  }

  auto& conversation = it->second;
  return conversation;
}

/// Generates a list of questions from the given DnsLayer
/// We can't use const as the methods we need in DnsLayer are not marked const
DnsEvent::QuestionList generateDnsQuestionList(pcpp::DnsLayer* dns_layer) {
  DnsEvent::QuestionList question_list;

  for (auto query = dns_layer->getFirstQuery(); query != nullptr;
       query = dns_layer->getNextQuery(query)) {
    DnsEvent::Question question = {};

    question.record_type = query->getDnsType();
    question.record_class = query->getDnsClass();
    question.record_name = query->getName();

    question_list.push_back(question);
  }

  return question_list;
}

/// Generates a list of answers from the given DnsLayer
/// We can't use const as the methods we need in DnsLayer are not marked const
DnsEvent::AnswerList generateDnsAnswerList(pcpp::DnsLayer* dns_layer) {
  DnsEvent::AnswerList answer_list;

  for (auto raw_answer = dns_layer->getFirstAnswer(); raw_answer != nullptr;
       raw_answer = dns_layer->getNextAnswer(raw_answer)) {
    DnsEvent::Answer answer = {};

    answer.ttl = raw_answer->getTTL();
    answer.record_data = raw_answer->getDataAsString();
    answer.record_type = raw_answer->getDnsType();
    answer.record_class = raw_answer->getDnsClass();
    answer.record_name = raw_answer->getName();

    answer_list.push_back(answer);
  }

  return answer_list;
}

/// Generates a new DNS event from the given DNS layer
/// Notes: we can't use const because the methods we need in pcpp::DnsLayer are
/// not marked as const
DnsEvent generateDnsEvent(pcpp::ProtocolType protocol,
                          pcpp::DnsLayer* dns_layer) {
  DnsEvent dns_event = {};

  const auto& dns_header = *dns_layer->getDnsHeader();

  dns_event.id = dns_header.transactionID;
  dns_event.protocol = protocol;
  dns_event.truncated = dns_header.truncation;
  dns_event.type = (dns_header.queryOrResponse == 0) ? DnsEvent::Type::Query
                                                     : DnsEvent::Type::Response;

  dns_event.question = generateDnsQuestionList(dns_layer);
  if (dns_header.queryOrResponse == 0) {
    return dns_event;
  }

  dns_event.answer = generateDnsAnswerList(dns_layer);
  return dns_event;
}

/// Generates new DNS events from the given TCP stream
/// Notes: we can't use const since Pcap++ expects writable buffers
osquery::Status generateDnsEventFromTCPData(DnsEventList& dns_event_list,
                                            ByteVector& tcp_stream) {
  try {
    dns_event_list = {};

    auto buffer_ptr = tcp_stream.data();
    auto buffer_end = buffer_ptr + tcp_stream.size();

    while (buffer_ptr < buffer_end) {
      if (buffer_ptr + 2U > buffer_end) {
        return osquery::Status(1, "Missing request size in TCP stream");
      }

      auto chunk_size = *reinterpret_cast<const std::uint16_t*>(buffer_ptr);
      chunk_size = htons(chunk_size);

      auto chunk_start = buffer_ptr + 2U;
      auto chunk_end = chunk_start + chunk_size;

      if (chunk_end > buffer_end) {
        return osquery::Status(1, "Invalid request size in TCP stream");
      }

      // The DnsLayer wil always attempt to free the buffer
      auto* temp_buffer = new std::uint8_t[chunk_size];
      std::memcpy(temp_buffer, chunk_start, chunk_size);

      pcpp::DnsLayer dns_layer(temp_buffer, chunk_size, nullptr, nullptr);

      auto dns_event = generateDnsEvent(pcpp::TCP, &dns_layer);
      dns_event_list.push_back(dns_event);

      buffer_ptr = chunk_end;
    }

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");
  }
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
      d->pcap, interface_name, kCaptureBufferSize, kPacketCaptureTimeout);

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
  std::vector<DnsEvent> dns_event_list;

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
      auto dns_layer = packet.getLayerOfType<pcpp::DnsLayer>();
      if (dns_layer == nullptr) {
        continue;
      }

      auto dns_event = generateDnsEvent(pcpp::UDP, dns_layer);
      dns_event.event_time = packet_header->ts;

      auto ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
      if (ipv4_layer != nullptr) {
        dns_event.source_address = ipv4_layer->getSrcIpAddress().toString();
        dns_event.destination_address =
            ipv4_layer->getDstIpAddress().toString();

      } else {
        auto ipv6_layer = packet.getLayerOfType<pcpp::IPv6Layer>();
        if (ipv6_layer != nullptr) {
          dns_event.source_address = ipv6_layer->getSrcIpAddress().toString();
          dns_event.destination_address =
              ipv6_layer->getDstIpAddress().toString();
        } else {
          LOG(ERROR)
              << "Failed to determine the source and destination IP addresses";
        }
      }

      dns_event_list.push_back(std::move(dns_event));

    } else {
      d->tcp_reassembler->reassemblePacket(&raw_packet);
    }
  }

  for (auto& p : d->completed_tcp_conversation_map) {
    auto& tcp_conversation = p.second;
    const auto& connection_data = tcp_conversation.connection_data;

    DnsEventList new_dns_event_list = {};
    auto status = generateDnsEventFromTCPData(new_dns_event_list,
                                              tcp_conversation.sent_data);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();

    } else {
      for (auto& event : new_dns_event_list) {
        event.source_address = connection_data.srcIP->toString();
        event.destination_address = connection_data.dstIP->toString();
        event.event_time = tcp_conversation.event_time;
      }

      dns_event_list.insert(dns_event_list.end(),
                            new_dns_event_list.begin(),
                            new_dns_event_list.end());
    }

    status = generateDnsEventFromTCPData(new_dns_event_list,
                                         tcp_conversation.received_data);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();

    } else {
      for (auto& event : new_dns_event_list) {
        event.destination_address = connection_data.srcIP->toString();
        event.source_address = connection_data.dstIP->toString();
        event.event_time = tcp_conversation.event_time;
      }

      dns_event_list.insert(dns_event_list.end(),
                            new_dns_event_list.begin(),
                            new_dns_event_list.end());
    }
  }

  d->completed_tcp_conversation_map.clear();

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  event_context->event_list = std::move(dns_event_list);
  dns_event_list.clear();

  emitEvents(event_context);
  return osquery::Status(0);
}

void DNSEventsPublisher::onTcpMessageReady(int side,
                                           pcpp::TcpStreamData tcp_data) {
  auto connection_data = tcp_data.getConnectionData();
  auto conversation_id = connection_data.flowKey;

  auto& conversation = getPendingTcpConversation(d, conversation_id);

  auto& stream_buffer =
      (side == 1) ? conversation.received_data : conversation.sent_data;

  auto data_length = static_cast<std::size_t>(tcp_data.getDataLength());
  const auto data_begin = tcp_data.getData();
  const auto data_end = data_begin + data_length;

  stream_buffer.reserve(stream_buffer.size() + data_length);
  stream_buffer.insert(stream_buffer.end(), data_begin, data_end);
}

void DNSEventsPublisher::onTcpConnectionStart(
    pcpp::ConnectionData connection_data) {
  auto conversation_id = connection_data.flowKey;
  auto& conversation = getPendingTcpConversation(d, conversation_id);

  conversation.connection_data = connection_data;

  gettimeofday(&conversation.event_time, nullptr);
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
