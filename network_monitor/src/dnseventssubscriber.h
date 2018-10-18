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

#include "dnseventspublisher.h"

#include <pubsub/subscriberregistry.h>
#include <pubsub/table_generator.h>

namespace trailofbits {
class DNSEventsSubscriber final
    : public BaseEventSubscriber<DNSEventsPublisher> {
 public:
  /// Returns the friendly publisher name
  static const char* name() {
    return "dns_events";
  }

  /// Factory function
  static osquery::Status create(IEventSubscriberRef& subscriber);

  /// One-time initialization
  virtual osquery::Status initialize() noexcept override;

  /// One-time deinitialization
  virtual void release() noexcept override;

  /// Called each time the configuration changes
  virtual osquery::Status configure(
      DNSEventsPublisher::SubscriptionContextRef subscription_context,
      const json11::Json& configuration) noexcept override;

  virtual osquery::Status callback(
      osquery::QueryData& new_events,
      DNSEventsPublisher::SubscriptionContextRef subscription_context,
      DNSEventsPublisher::EventContextRef event_context) override;
};

DECLARE_SUBSCRIBER(DNSEventsPublisher, DNSEventsSubscriber);

// clang-format off
BEGIN_TABLE(dns_events)
  // Event time, equal to the capture time
  TABLE_COLUMN(event_time, osquery::TEXT_TYPE)

  // Source and destination hosts
  TABLE_COLUMN(source_address, osquery::TEXT_TYPE)
  TABLE_COLUMN(destination_address, osquery::TEXT_TYPE)

  // DNS header information
  TABLE_COLUMN(protocol, osquery::TEXT_TYPE)
  TABLE_COLUMN(truncated, osquery::TEXT_TYPE)
  TABLE_COLUMN(id, osquery::TEXT_TYPE)
  TABLE_COLUMN(type, osquery::TEXT_TYPE)

  // Columns used by both queries and responses
  TABLE_COLUMN(record_type, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_class, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_name, osquery::TEXT_TYPE)

  // Columns only used by responses
  TABLE_COLUMN(ttl, osquery::TEXT_TYPE)
  TABLE_COLUMN(record_data, osquery::TEXT_TYPE)
END_TABLE(dns_events)
// clang-format on
} // namespace trailofbits
