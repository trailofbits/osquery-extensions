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
#include "pcapreaderservice.h"

#include <IPv4Layer.h>
#include <IPv6Layer.h>

namespace trailofbits {
namespace {
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
osquery::Status generateDnsEventListFromTCPStream(DnsEventList& dns_event_list,
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

void appendDnsEventListFromTCPConversation(DnsEventList& dns_event_list,
                                           TcpConversation& tcp_conversation) {
  std::vector<std::reference_wrapper<ByteVector>> stream_list = {
      tcp_conversation.sent_data, tcp_conversation.received_data};

  const auto& connection_data = tcp_conversation.connection_data;
  std::size_t side = 0;

  for (auto& stream_data : stream_list) {
    DnsEventList new_events = {};
    auto status = generateDnsEventListFromTCPStream(new_events, stream_data);

    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    for (auto& event : new_events) {
      if (side == 0) {
        event.source_address = connection_data.srcIP->toString();
        event.destination_address = connection_data.dstIP->toString();
      } else {
        event.source_address = connection_data.dstIP->toString();
        event.destination_address = connection_data.srcIP->toString();
      }

      event.event_time = tcp_conversation.event_time;
    }

    dns_event_list.insert(
        dns_event_list.end(), new_events.begin(), new_events.end());

    side++;
  }
}
} // namespace

/// Private class data
struct DNSEventsPublisher::PrivateData final {
  /// The service that pulls data from pcap
  PcapReaderServiceRef pcap_reader_service;

  /// Data shared with the pcap reader service
  PcapReaderServiceData pcap_service_data;
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
  return ServiceManager::instance().createService<PcapReaderService>(
      d->pcap_reader_service, d->pcap_service_data);
}

osquery::Status DNSEventsPublisher::release() noexcept {
  return osquery::Status(0);
}

osquery::Status DNSEventsPublisher::configure(
    const json11::Json& configuration) noexcept {
  return d->pcap_reader_service->configure(configuration);
}

osquery::Status DNSEventsPublisher::run() noexcept {
  UDPRequestList udp_request_list;
  TcpConversationMap completed_tcp_conversation_map;
  pcpp::LinkLayerType link_type{pcpp::LINKTYPE_NULL};

  {
    std::unique_lock<std::mutex> lock(d->pcap_service_data.mutex);

    if (d->pcap_service_data.cv.wait_for(lock, std::chrono::seconds(1)) !=
        std::cv_status::no_timeout) {
      return osquery::Status(0);
    }

    udp_request_list = std::move(d->pcap_service_data.udp_request_list);
    completed_tcp_conversation_map =
        std::move(d->pcap_service_data.completed_tcp_conversation_map);

    d->pcap_service_data.udp_request_list.clear();
    d->pcap_service_data.completed_tcp_conversation_map.clear();

    link_type = d->pcap_service_data.link_type;
  }

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  // Process the UDP requests
  for (const auto& udp_request : udp_request_list) {
    const auto& timestamp = udp_request.first;
    const auto& packet_data = udp_request.second;

    auto packet_data_length = static_cast<int>(packet_data.size());

    pcpp::RawPacket raw_packet(
        packet_data.data(), packet_data_length, timestamp, false, link_type);

    pcpp::Packet packet(&raw_packet);
    auto dns_layer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (dns_layer == nullptr) {
      continue;
    }

    auto dns_event = generateDnsEvent(pcpp::UDP, dns_layer);
    dns_event.event_time = timestamp;

    auto ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4_layer != nullptr) {
      dns_event.source_address = ipv4_layer->getSrcIpAddress().toString();

      dns_event.destination_address = ipv4_layer->getDstIpAddress().toString();

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

    event_context->event_list.push_back(std::move(dns_event));
  }

  // Process the TCP requests
  for (auto& p : completed_tcp_conversation_map) {
    auto& tcp_conversation = p.second;
    appendDnsEventListFromTCPConversation(event_context->event_list,
                                          tcp_conversation);
  }

  emitEvents(event_context);
  return osquery::Status(0);
}
} // namespace trailofbits
