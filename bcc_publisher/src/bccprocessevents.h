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

#include "bccprocesseventspublisher.h"

#include <pubsub/subscriberregistry.h>
#include <pubsub/table_generator.h>

namespace trailofbits {
class BCCProcessEvents final
    : public BaseEventSubscriber<BCCProcessEventsPublisher> {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BCCProcessEvents();

 public:
  static const char* name() {
    return "bcc_process_events";
  }

  static osquery::Status create(IEventSubscriberRef& subscriber);

  virtual ~BCCProcessEvents();

  virtual osquery::Status initialize() noexcept override;
  virtual void release() noexcept override;

  virtual osquery::Status configure(
      BCCProcessEventsPublisher::SubscriptionContextRef subscription_context,
      const json11::Json& configuration) noexcept override;

  virtual osquery::Status callback(
      osquery::QueryData& new_events,
      BCCProcessEventsPublisher::SubscriptionContextRef subscription_context,
      BCCProcessEventsPublisher::EventContextRef event_context) override;
};

DECLARE_SUBSCRIBER(BCCProcessEventsPublisher, BCCProcessEvents);
} // namespace trailofbits
