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

#include "pcapreaderservice.h"

#include <sstream>

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>

#include <osquery/logger.h>

namespace trailofbits {
namespace {
/// Capture buffer size
const int kCaptureBufferSize = 1048576;

/// The buffer timeout is used to aggregate multiple packets into a single event
const int kCaptureBufferTimeout = 1000;

/// Max TCP conversation size
const std::size_t kMaxTcpConversationLength = 10240U;

/// When an inactive connection should be forcefully dropped
const std::size_t kMaxTcpConversationIdleTime = 30U;

/// The eBPF program used to filter the packets
const std::string kFilterRules = "port 53 and (tcp or udp)";
} // namespace

void PcapReaderService::onTcpMessageReady(int side,
                                          pcpp::TcpStreamData tcp_data) {
  auto connection_data = tcp_data.getConnectionData();
  auto conversation_id = connection_data.flowKey;

  auto& conversation = getPendingTcpConversation(conversation_id);

  auto& stream_buffer =
      (side == 1) ? conversation.received_data : conversation.sent_data;

  if (stream_buffer.size() >= kMaxTcpConversationLength) {
    pending_tcp_conversation_map.erase(conversation_id);
    tcp_conversation_timestamp_map.erase(conversation_id);

    std::stringstream message;
    message << "Dropping conversation between '"
            << tcp_data.getConnectionData().srcIP->toString() << "' and '"
            << tcp_data.getConnectionData().dstIP->toString() << "' because "
            << "the conversation size is above the max limit";

    LOG(WARNING) << message.str();
    return;
  }

  auto data_length = static_cast<std::size_t>(tcp_data.getDataLength());
  const auto data_begin = tcp_data.getData();
  const auto data_end = data_begin + data_length;

  stream_buffer.reserve(stream_buffer.size() + data_length);
  stream_buffer.insert(stream_buffer.end(), data_begin, data_end);

  tcp_conversation_timestamp_map[conversation_id] = std::time(nullptr);
}

void PcapReaderService::onTcpConnectionStart(
    pcpp::ConnectionData connection_data) {
  auto conversation_id = connection_data.flowKey;
  auto& conversation = getPendingTcpConversation(conversation_id);

  conversation.connection_data = connection_data;
  gettimeofday(&conversation.event_time, nullptr);

  tcp_conversation_timestamp_map[conversation_id] = std::time(nullptr);
}

void PcapReaderService::onTcpConnectionEnd(
    pcpp::ConnectionData connection_data,
    pcpp::TcpReassembly::ConnectionEndReason) {
  auto conversation_id = connection_data.flowKey;

  auto it = pending_tcp_conversation_map.find(conversation_id);
  if (it == pending_tcp_conversation_map.end()) {
    return;
  }

  auto& conversation = it->second;
  completed_tcp_conversation_map.insert(
      {conversation_id, std::move(conversation)});

  pending_tcp_conversation_map.erase(it);
  tcp_conversation_timestamp_map.erase(conversation_id);
}

TcpConversation& PcapReaderService::getPendingTcpConversation(
    TcpConversationId identifier) {
  auto it = pending_tcp_conversation_map.find(identifier);
  if (it == pending_tcp_conversation_map.end()) {
    auto insert_res = pending_tcp_conversation_map.insert({identifier, {}});
    it = insert_res.first;
  }

  auto& conversation = it->second;
  return conversation;
}

PcapReaderService::PcapReaderService(PcapReaderServiceData& shared_data_)
    : shared_data(shared_data_) {}

osquery::Status PcapReaderService::initialize() {
  return osquery::Status(0);
}

osquery::Status PcapReaderService::configure(
    const json11::Json& configuration) {
  if (!configuration.is_object()) {
    LOG(ERROR) << "Invalid configuration";
    return osquery::Status(0);
  }

  const auto& dns_event_configuration = configuration["dns_events"];
  if (dns_event_configuration == json11::Json()) {
    LOG(ERROR) << "The 'dns_events' configuration section is missing";
    return osquery::Status(0);
  }

  const auto& interface_name_obj = dns_event_configuration["interface"];
  if (interface_name_obj == json11::Json()) {
    LOG(ERROR)
        << "The 'interface' value is missing from the 'dns_events' section";

    return osquery::Status(0);
  }

  auto interface_name = interface_name_obj.string_value();

  const auto& promiscuous_mode_obj = dns_event_configuration["promiscuous"];
  if (promiscuous_mode_obj == json11::Json()) {
    LOG(ERROR)
        << "The 'promiscuous' value is missing from the 'dns_events' section";

    return osquery::Status(0);
  }

  auto promiscuous_mode = promiscuous_mode_obj.bool_value();

  std::lock_guard<std::mutex> lock(pcap_mutex);

  auto status = createPcap(pcap,
                           interface_name,
                           kCaptureBufferSize,
                           kCaptureBufferTimeout,
                           promiscuous_mode);

  if (!status.ok()) {
    return status;
  }

  auto pcap_link_type = pcap_datalink(pcap.get());
  if (pcap_link_type == PCAP_ERROR_NOT_ACTIVATED) {
    return osquery::Status::failure(
        "Failed to acquire the link-layer header type");
  }

  bool valid_link_header_type = false;
  switch (pcap_link_type) {
  case DLT_IPV4: {
    shared_data.link_type = pcpp::LINKTYPE_IPV4;
    valid_link_header_type = true;
    break;
  }

  case DLT_IPV6: {
    shared_data.link_type = pcpp::LINKTYPE_IPV6;
    valid_link_header_type = true;
    break;
  }

  case DLT_EN10MB: {
    shared_data.link_type = pcpp::LINKTYPE_ETHERNET;
    valid_link_header_type = true;
    break;
  }

  default:
    break;
  }

  if (!valid_link_header_type) {
    return osquery::Status::failure("Invalid link-layer header type");
  }

  status = getNetworkDeviceInformation(device_information, interface_name);
  if (!status.ok()) {
    return status;
  }

  if (!device_information.ipv4_address_list.empty()) {
    std::stringstream log_message;

    log_message << "Listening on the following IPv4 addresses:";
    for (const auto& network_address : device_information.ipv4_address_list) {
      log_message << " " << network_address.address << "/"
                  << network_address.netmask;
    }

    LOG(INFO) << log_message.str();
  }

  if (!device_information.ipv6_address_list.empty()) {
    std::stringstream log_message;

    log_message << "Listening on the following IPv6 addresses:";
    for (const auto& network_address : device_information.ipv6_address_list) {
      log_message << " " << network_address.address << "/"
                  << network_address.netmask;
    }

    LOG(INFO) << log_message.str();
  }

  if (pcap_compile(pcap.get(),
                   &ebpf_filter_program,
                   kFilterRules.c_str(),
                   1,
                   PCAP_NETMASK_UNKNOWN) != 0) {
    auto error_message = std::string("Failed to compile the eBPF filter: ") +
                         pcap_geterr(pcap.get());

    return osquery::Status::failure(error_message);
  }

  if (pcap_setfilter(pcap.get(), &ebpf_filter_program) != 0) {
    auto error_message =
        std::string("Failed to enable the eBPF filter program: ") +
        pcap_geterr(pcap.get());

    return osquery::Status::failure(error_message);
  }

  static auto L_onTcpMessageReady =
      [](int side, pcpp::TcpStreamData tcp_data, void* user_cookie) -> void {
    auto& service = *reinterpret_cast<PcapReaderService*>(user_cookie);
    service.onTcpMessageReady(side, tcp_data);
  };

  static auto L_onTcpConnectionStart = [](pcpp::ConnectionData connection_data,
                                          void* user_cookie) -> void {
    auto& service = *reinterpret_cast<PcapReaderService*>(user_cookie);
    service.onTcpConnectionStart(connection_data);
  };

  static auto L_onTcpConnectionEnd =
      [](pcpp::ConnectionData connection_data,
         pcpp::TcpReassembly::ConnectionEndReason reason,
         void* user_cookie) -> void {
    auto& service = *reinterpret_cast<PcapReaderService*>(user_cookie);
    service.onTcpConnectionEnd(connection_data, reason);
  };

  tcp_reassembler = std::make_unique<pcpp::TcpReassembly>(
      L_onTcpMessageReady, this, L_onTcpConnectionStart, L_onTcpConnectionEnd);

  return osquery::Status(0);
}

void PcapReaderService::release() {}

void PcapReaderService::run() {
  while (!shouldTerminate()) {
    // Acquire as many packets as we can
    UDPRequestList new_udp_requests = {};

    while (!shouldTerminate()) {
      pcap_pkthdr* packet_header = nullptr;
      const std::uint8_t* packet_data_buffer = nullptr;
      bool uninitialized = true;

      {
        std::lock_guard<std::mutex> lock(pcap_mutex);

        if (pcap) {
          uninitialized = false;

          bool timed_out = false;
          auto status = waitForNewPackets(timed_out, pcap, 1000U);
          if (!status.ok()) {
            LOG(ERROR) << "Failed to capture the next packet: "
                       << status.getMessage();

            return;
          }

          if (timed_out) {
            break;
          }

          auto capture_error =
              pcap_next_ex(pcap.get(), &packet_header, &packet_data_buffer);

          if (capture_error == -1) {
            LOG(ERROR) << "Failed to capture the next packet: "
                       << pcap_geterr(pcap.get()) << ". Halting...";

            return;
          }
        }
      }

      if (uninitialized) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        continue;
      }

      pcpp::RawPacket raw_packet(packet_data_buffer,
                                 static_cast<int>(packet_header->len),
                                 packet_header->ts,
                                 false,
                                 shared_data.link_type);

      pcpp::Packet packet(&raw_packet);

      if (packet.isPacketOfType(pcpp::UDP)) {
        ByteVector udp_request_data(packet_header->len);
        udp_request_data.assign(packet_data_buffer,
                                packet_data_buffer + packet_header->len);

        auto udp_request =
            std::make_pair(packet_header->ts, std::move(udp_request_data));

        new_udp_requests.push_back(std::move(udp_request));

      } else {
        bool process_packet = false;
        if (packet.isPacketOfType(pcpp::IPv4) ||
            packet.isPacketOfType(pcpp::IPv6)) {
          process_packet = (packet.getLayerOfType<pcpp::TcpLayer>() != nullptr);
        }

        if (process_packet) {
          tcp_reassembler->reassemblePacket(&raw_packet);
        }
      }
    }

    // Move new data into the shared structure so that the publisher can start
    // emitting new rows into the table
    if (!new_udp_requests.empty() || !completed_tcp_conversation_map.empty()) {
      std::lock_guard<std::mutex> lock(shared_data.mutex);

      auto& udp_request_buffer = shared_data.udp_request_list;
      if (!new_udp_requests.empty()) {
        if (udp_request_buffer.empty()) {
          udp_request_buffer = std::move(new_udp_requests);
        } else {
          udp_request_buffer.reserve(udp_request_buffer.size() +
                                     new_udp_requests.size());

          std::move(new_udp_requests.begin(),
                    new_udp_requests.end(),
                    std::back_inserter(udp_request_buffer));
        }

        new_udp_requests.clear();
      }

      auto& tcp_conversation_buffer =
          shared_data.completed_tcp_conversation_map;

      if (!completed_tcp_conversation_map.empty()) {
        if (tcp_conversation_buffer.empty()) {
          tcp_conversation_buffer = std::move(completed_tcp_conversation_map);
        } else {
          tcp_conversation_buffer.reserve(
              tcp_conversation_buffer.size() +
              completed_tcp_conversation_map.size());

          tcp_conversation_buffer.insert(completed_tcp_conversation_map.begin(),
                                         completed_tcp_conversation_map.end());
        }

        completed_tcp_conversation_map.clear();
      }

      shared_data.cv.notify_all();
    }

    auto current_time = std::time(nullptr);

    for (auto it = tcp_conversation_timestamp_map.begin();
         it != tcp_conversation_timestamp_map.end();) {
      const auto& conversation_id = it->first;
      const auto& last_update = it->second;

      auto elapsed_time = static_cast<std::size_t>(current_time - last_update);
      if (elapsed_time > kMaxTcpConversationIdleTime) {
        it = tcp_conversation_timestamp_map.erase(it);

        pending_tcp_conversation_map.erase(conversation_id);
        tcp_reassembler->closeConnection(conversation_id);

        LOG(WARNING) << "Dropping connection " << conversation_id;
      } else {
        ++it;
      }
    }
  }
}
} // namespace trailofbits
