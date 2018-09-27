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

#include "networkeventpublisher.h"
#include "subscriberregistry.h"

namespace trailofbits {
class NetworkEventSubscriber final
    : public BaseEventSubscriber<NetworkEventPublisher> {
 public:
  /// Returns the friendly publisher name
  static const char* name() {
    return "network_events";
  }

  /// Factory function
  static osquery::Status create(IEventSubscriberRef& subscriber);

  /// One-time initialization
  virtual osquery::Status initialize() noexcept override;

  /// One-time deinitialization
  virtual void release() noexcept override;

  /// Called each time the configuration changes
  virtual osquery::Status configure() noexcept override;

  virtual osquery::Status callback(
      NetworkEventPublisher::SubscriptionContextRef subscription_context,
      NetworkEventPublisher::EventContextRef event_context) override;
};

DECLARE_SUBSCRIBER(NetworkEventPublisher, NetworkEventSubscriber);
} // namespace trailofbits
