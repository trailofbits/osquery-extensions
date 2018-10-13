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
  /*for (const auto& dns_request_ref : completed_request_list) {
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
  }*/

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
