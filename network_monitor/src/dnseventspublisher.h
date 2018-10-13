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

#include <pubsub/publisherregistry.h>

#include <TcpReassembly.h>

#include <memory>
#include <string>

#include <sys/time.h>

namespace trailofbits {
class DNSEventsPublisher;

/// A reference to a DNSEventsPublisher object
struct DNSEventSubscriptionContext final {};

/// Packet data
using PacketData = std::vector<std::uint8_t>;

/// This comparator allows us to use the `struct timeval` type as a key
/// for ordered containers
struct TimevalComparator final {
  bool operator()(const struct timeval& l, const struct timeval& r) const {
    if (l.tv_sec != r.tv_sec) {
      return l.tv_sec < r.tv_sec;
    }

    return l.tv_usec < r.tv_usec;
  }
};

/// A timestamp-sorted list of packets
using PacketList = std::map<struct timeval, PacketData, TimevalComparator>;

/// The event object emitted by this publisher
struct DNSEventData final {};

/// A network sniffer based on libcap
class DNSEventsPublisher final
    : public BaseEventPublisher<DNSEventSubscriptionContext, DNSEventData> {
 public:
  struct PrivateData;

 private:
  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use the ::create() static function instead
  explicit DNSEventsPublisher();

 public:
  /// Factory function used to create DNSEventsPublisher objects
  static osquery::Status create(IEventPublisherRef& publisher);

  /// Returns the friendly publisher name
  static const char* name() {
    return "dns_events_publisher";
  }

  /// Destructor
  virtual ~DNSEventsPublisher() = default;

  /// One-time initialization
  osquery::Status initialize() noexcept override;

  /// One-time deinitialization
  osquery::Status release() noexcept override;

  /// Called each time the configuration changes
  osquery::Status configure(
      const json11::Json& configuration) noexcept override;

  /// Worker method; should perform some work and then return
  osquery::Status run() noexcept override;

  /// Automatically called by the TCP reassembler when new data is available
  void onTcpMessageReady(int side, pcpp::TcpStreamData tcp_data);

  /// Automatically called by the TCP reassembler when a connection is started
  void onTcpConnectionStart(pcpp::ConnectionData connection_data);

  /// Automatically called by the TCP reassembler when a connection ends
  void onTcpConnectionEnd(pcpp::ConnectionData connection_data,
                          pcpp::TcpReassembly::ConnectionEndReason reason);

  /// Disable the copy constructor
  DNSEventsPublisher(const DNSEventsPublisher& other) = delete;

  /// Disable the assignment operator
  DNSEventsPublisher& operator=(const DNSEventsPublisher& other) = delete;
};

DECLARE_PUBLISHER(DNSEventsPublisher);
} // namespace trailofbits
