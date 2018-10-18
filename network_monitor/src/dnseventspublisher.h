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

#include <DnsLayer.h>
#include <TcpReassembly.h>

#include <memory>
#include <string>

#include <sys/time.h>

namespace trailofbits {
class DNSEventsPublisher;

/// A reference to a DNSEventsPublisher object
struct DNSEventSubscriptionContext final {};

/// A single DNS event
struct DnsEvent final {
  /// Event time
  timeval event_time{};

  /// Source address
  std::string source_address;

  /// Destination address
  std::string destination_address;

  /// Request type, taken from the qr bit of the header
  enum class Type { Query, Response };

  /// Describes a single question in the DNS request
  struct Question final {
    /// Record type (i.e.: A, NS, CNAME, etc...)
    pcpp::DnsType record_type;

    /// DNS class (i.e.: IN, CH, etc...)
    pcpp::DnsClass record_class;

    /// The domain name
    std::string record_name;
  };

  /// A list of questions sent to the DNS server
  using QuestionList = std::vector<Question>;

  /// Answer data
  struct Answer final {
    /// The time to live for this record
    std::uint32_t ttl;

    /// The record data
    std::string record_data;

    /// The record type (i.e.: A, NS or CNAME)
    pcpp::DnsType record_type;

    /// The class for this record (such as IN, CH or ANY)
    pcpp::DnsClass record_class;

    /// The record name
    std::string record_name;
  };

  /// A list of answers received from the DNS server
  using AnswerList = std::vector<Answer>;

  /// Request type; either a query or a response
  Type type{Type::Query};

  /// List of questions sent or received (copied from the client request) from
  /// the DNS server
  QuestionList question;

  /// List of answers received from the DNS server
  AnswerList answer;

  /// Request identifier
  std::uint16_t id;

  /// Protocol type; either UDP or TCP
  pcpp::ProtocolType protocol{pcpp::UDP};

  /// True if the request was truncated; only valid when the protocol is set to
  /// UDP
  bool truncated{false};
};

/// A list of DNS events
using DnsEventList = std::vector<DnsEvent>;

/// The event object emitted by this publisher
struct DNSEventData final {
  /// A list of DNS events
  DnsEventList event_list;
};

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
