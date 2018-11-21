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
#include <pubsub/servicemanager.h>

#include "bccprocesseventsprogram.h"

namespace trailofbits {
struct BCCProcessEventsPublisherSubscriptionContext final {};

struct BCCProcessEventsPublisherData final {
  ProcessEventList event_list;
};

class BCCProcessEventsPublisher final
    : public BaseEventPublisher<BCCProcessEventsPublisherSubscriptionContext,
                                BCCProcessEventsPublisherData> {
 protected:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  explicit BCCProcessEventsPublisher();

 public:
  static osquery::Status create(IEventPublisherRef& publisher);

  static const char* name() {
    return "BCCProcessEventsPublisher_Publisher";
  }

  virtual ~BCCProcessEventsPublisher() override = default;

  osquery::Status initialize() noexcept override;

  osquery::Status release() noexcept override;

  osquery::Status onConfigurationChangeStart(
      const json11::Json& configuration) noexcept override;

  osquery::Status onConfigurationChangeEnd(
      const json11::Json& configuration) noexcept override;

  osquery::Status onSubscriberConfigurationChange(
      const json11::Json& configuration,
      SubscriberType& subscriber,
      SubscriptionContextRef subscription_context) noexcept override;

  osquery::Status updatePublisher() noexcept override;

  osquery::Status updateSubscriber(
      IEventSubscriberRef subscriber,
      SubscriptionContextRef subscription_context) noexcept override;

  BCCProcessEventsPublisher(const BCCProcessEventsPublisher& other) = delete;

  BCCProcessEventsPublisher& operator=(const BCCProcessEventsPublisher& other) =
      delete;
};

DECLARE_PUBLISHER(BCCProcessEventsPublisher);
} // namespace trailofbits
