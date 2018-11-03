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

#include "ieventsubscriber.h"

#include <osquery/status.h>

#include <memory>

namespace trailofbits {
/// Common base class for event publishers
class IEventPublisher {
 public:
  /// Subscribers the specified object to events emitted by this publisher
  virtual osquery::Status subscribe(IEventSubscriberRef subscriber) = 0;

  /// Unsubscribes the specified object
  virtual void unsubscribe(IEventSubscriberRef subscriber) = 0;

  /// One-time initialization
  virtual osquery::Status initialize() noexcept = 0;

  /// Forwards the configuration change to the subscribers
  virtual osquery::Status configure(
      const json11::Json& configuration) noexcept = 0;

  ///
  virtual osquery::Status updateSubscribers() noexcept = 0;

  /// Called each time the configuration changes
  virtual osquery::Status onConfigurationChangeStart(
      const json11::Json& configuration) noexcept = 0;

  /// Called each time the configuration changes
  virtual osquery::Status onConfigurationChangeEnd(
      const json11::Json& configuration) noexcept = 0;

  /// One-time deinitialization
  virtual osquery::Status release() noexcept = 0;

  /// Worker method; should perform some work and then return
  virtual osquery::Status updatePublisher() noexcept = 0;

  /// Returns the amount of active subscribers
  virtual std::size_t subscriptionCount() noexcept = 0;

  /// Destructor
  virtual ~IEventPublisher() = default;
};

/// A reference to an event publisher
using IEventPublisherRef = std::shared_ptr<IEventPublisher>;
} // namespace trailofbits
