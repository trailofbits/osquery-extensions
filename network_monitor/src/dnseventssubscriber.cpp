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

#include "dnseventssubscriber.h"

#include <pubsub/table_generator.h>

namespace trailofbits {
namespace {
std::ostream& operator<<(std::ostream& stream, const IPAddress& ip_address) {
  switch (ip_address.ip_protocol) {
  case IPProtocol::IPv4: {
    const auto& address = boost::get<u_int32_t>(ip_address.address);

    auto components = reinterpret_cast<const std::uint8_t*>(&address);
    stream << static_cast<std::uint32_t>(components[0]) << "."
           << static_cast<std::uint32_t>(components[1]) << "."
           << static_cast<std::uint32_t>(components[2]) << "."
           << static_cast<std::uint32_t>(components[3]);

    break;
  }

  case IPProtocol::IPv6: {
    const auto& address = boost::get<in6_addr>(ip_address.address);

    for (auto i = 0U; i < 16U; i++) {
      stream << address.__in6_u.__u6_addr8;
      if (i + 1 < 16U) {
        stream << ":";
      }
    }

    break;
  }
  }

  return stream;
}

std::string ipAddressToString(const IPAddress& address) {
  std::stringstream buffer;
  buffer << address;

  return buffer.str();
}
} // namespace

osquery::Status DNSEventsSubscriber::create(IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new DNSEventsSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status DNSEventsSubscriber::initialize() noexcept {
  return osquery::Status(0);
}

void DNSEventsSubscriber::release() noexcept {}

osquery::Status DNSEventsSubscriber::configure(
    DNSEventsPublisher::SubscriptionContextRef subscription_context,
    const json11::Json& configuration) noexcept {
  static_cast<void>(subscription_context);
  static_cast<void>(configuration);

  return osquery::Status(0);
}

osquery::Status DNSEventsSubscriber::callback(
    osquery::QueryData& new_events,
    DNSEventsPublisher::SubscriptionContextRef subscription_context,
    DNSEventsPublisher::EventContextRef event_context) {
  std::vector<DNSRequestRef> completed_request_list;

  for (const auto& p : event_context->packet_list) {
    const auto& timestamp = p.first;
    const auto& packet_data = p.second;

    PacketRef packet_ref;
    auto status = Packet::create(
        packet_ref, event_context->link_type, timestamp.tv_sec, packet_data);

    if (!status.ok()) {
      LOG(ERROR) << "Failed to parse the packet at timestamp "
                 << timestamp.tv_sec << "." << timestamp.tv_usec << ": "
                 << status.getMessage();

      continue;
    }

    std::uint16_t request_id;
    status = DNSRequest::extractIdentifierFromPacket(request_id, packet_ref);
    if (!status.ok()) {
      LOG(ERROR)
          << "Failed to acquire the DNS request id for the packet at timestamp "
          << timestamp.tv_sec << "." << timestamp.tv_usec << ": "
          << status.getMessage();

      continue;
    }

    auto truncated_requests_it =
        subscription_context->truncated_requests.find(request_id);
    if (truncated_requests_it !=
        subscription_context->truncated_requests.end()) {
      auto dns_request_ref = truncated_requests_it->second;
      subscription_context->truncated_requests.erase(truncated_requests_it);

      status = dns_request_ref->appendPacket(packet_ref);
      if (!status.ok()) {
        LOG(ERROR) << "Failed to handle truncated the DNS request with id "
                   << request_id << " with packet timestamp "
                   << timestamp.tv_sec << "." << timestamp.tv_usec << ": "
                   << status.getMessage();

        continue;
      }

      if (dns_request_ref->isTruncated()) {
        subscription_context->truncated_requests.insert(
            {request_id, dns_request_ref});
      } else {
        completed_request_list.push_back(dns_request_ref);
      }
    }

    DNSRequestRef dns_request_ref;
    status = DNSRequest::create(dns_request_ref, packet_ref);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to parse the DNS request at timestamp "
                 << timestamp.tv_sec << "." << timestamp.tv_usec << ": "
                 << status.getMessage();

      continue;
    }

    if (dns_request_ref->isTruncated()) {
      subscription_context->truncated_requests.insert(
          {dns_request_ref->requestIdentifier(), dns_request_ref});
    } else {
      completed_request_list.push_back(dns_request_ref);
    }
  }

  for (const auto& dns_request_ref : completed_request_list) {
    auto source_address = dns_request_ref->sourceAddress();
    auto destination_address = dns_request_ref->destinationAddress();

    osquery::Row row = {};
    row["event_time"] = std::to_string(dns_request_ref->timestamp());

    row["ip_protocol"] =
        (dns_request_ref->ipProtocol() == IPProtocol::IPv4) ? "ipv4" : "ipv6";

    row["protocol"] =
        (dns_request_ref->protocol() == Protocol::TCP) ? "tcp" : "udp";

    row["source_address"] = ipAddressToString(source_address);
    row["destination_address"] = ipAddressToString(destination_address);

    new_events.push_back(std::move(row));
  }

  return osquery::Status(0);
}

// clang-format off
BEGIN_TABLE(dns_events)
  TABLE_COLUMN(event_time, osquery::TEXT_TYPE)
  TABLE_COLUMN(ip_protocol, osquery::TEXT_TYPE)
  TABLE_COLUMN(protocol, osquery::TEXT_TYPE)
  TABLE_COLUMN(source_address, osquery::TEXT_TYPE)
  TABLE_COLUMN(destination_address, osquery::TEXT_TYPE)
END_TABLE(dns_events)
// clang-format on
} // namespace trailofbits
