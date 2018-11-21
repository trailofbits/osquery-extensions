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

#include "baseeventsubscriber.h"
#include "ieventsubscriber.h"

#include <osquery/sdk.h>

namespace trailofbits {
/// Event subscribers use this as a base class
template <typename EventPublisher>
class BaseEventSubscriber : public IEventSubscriber {
 public:
  /// Called each time the configuration changes
  virtual osquery::Status configure(
      typename EventPublisher::SubscriptionContextRef subscription_context,
      const json11::Json& configuration) noexcept = 0;

  /// This method is called by the publishers when there is new data to be
  /// processed
  virtual osquery::Status callback(
      osquery::QueryData& new_events,
      typename EventPublisher::SubscriptionContextRef subscription_context,
      typename EventPublisher::EventContextRef event_context) = 0;
};
} // namespace trailofbits
