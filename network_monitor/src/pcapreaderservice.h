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

#include "pcap_utils.h"

#include <pubsub/servicemanager.h>

#include <DnsLayer.h>
#include <TcpReassembly.h>
#include <json11.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <sys/time.h>

namespace trailofbits {
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

/// A UDP request with its timestamp
using UDPRequest = std::pair<timeval, ByteVector>;

/// A list of UDP requests
using UDPRequestList = std::vector<UDPRequest>;

/// Data processed by the pcap reader service
struct PcapReaderServiceData final {
  /// Mutex used to protect the shared data
  std::mutex mutex;

  /// Condition variable, used to wake up the publisher thread
  std::condition_variable cv;

  /// A list of raw UDP requests, ready to be processed
  UDPRequestList udp_request_list;

  /// Completed TCP requests
  TcpConversationMap completed_tcp_conversation_map;

  /// Link type
  pcpp::LinkLayerType link_type;
};

/// A reference to a TCP reassembler object
using TcpReassemblyRef = std::unique_ptr<pcpp::TcpReassembly>;

/// This service pulls data from the pcap handle
class PcapReaderService final : public IService {
  /// Data shared with the publisher
  PcapReaderServiceData& shared_data;

  /// Contains device information such as IP addresses and netmasks
  NetworkDeviceInformation device_information;

  /// The pcap handle
  DeclarePcapRef(pcap);

  /// pcap mutex
  std::mutex pcap_mutex;

  /// The eBPF program used to filter the network traffic
  struct bpf_program ebpf_filter_program {};

  /// This class instance is used to reassemble TCP packets
  TcpReassemblyRef tcp_reassembler;

  /// Pending TCP conversations
  TcpConversationMap pending_tcp_conversation_map;

  /// Completed TCP conversations
  TcpConversationMap completed_tcp_conversation_map;

  /// Automatically called by the TCP reassembler when new data is available
  void onTcpMessageReady(int side, pcpp::TcpStreamData tcp_data);

  /// Automatically called by the TCP reassembler when a connection is started
  void onTcpConnectionStart(pcpp::ConnectionData connection_data);

  /// Automatically called by the TCP reassembler when a connection ends
  void onTcpConnectionEnd(pcpp::ConnectionData connection_data,
                          pcpp::TcpReassembly::ConnectionEndReason reason);

  /// Returns the specified pending TCP conversation (or creates a new one)
  TcpConversation& getPendingTcpConversation(TcpConversationId identifier);

 public:
  /// Constructor
  PcapReaderService(PcapReaderServiceData& shared_data_);

  /// Destructor
  virtual ~PcapReaderService() override = default;

  /// Initialization callback; optional
  virtual osquery::Status initialize() override;

  /// Configuration change
  virtual osquery::Status configure(const json11::Json& configuration);

  /// Cleanup callback; optional
  virtual void release() override;

  /// This is the service entry point
  virtual void run() override;
};

/// A reference to a PcapReaderService object
using PcapReaderServiceRef = std::shared_ptr<PcapReaderService>;
} // namespace trailofbits
