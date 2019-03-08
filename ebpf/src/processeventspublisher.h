/*
 * Copyright (c) 2019-present Trail of Bits, Inc.
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

#include "probereaderservice.h"

#include <pubsub/publisherregistry.h>
#include <pubsub/servicemanager.h>

#include <unordered_set>

namespace trailofbits {
struct ProcessEventsPublisherSubscriptionContext final {
  std::unordered_set<int> system_call_filter;
};

struct ProcessEventsPublisherData final {
  ProbeEventList probe_event_list;
};

class ProcessEventsPublisher final
    : public BaseEventPublisher<ProcessEventsPublisherSubscriptionContext,
                                ProcessEventsPublisherData> {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 protected:
  ProcessEventsPublisher();

 public:
  static osquery::Status create(IEventPublisherRef& publisher);

  static const char* name() {
    return "ProcessEventsPublisher";
  }

  virtual ~ProcessEventsPublisher() override = default;

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

  ProcessEventsPublisher(const ProcessEventsPublisher& other) = delete;

  ProcessEventsPublisher& operator=(const ProcessEventsPublisher& other) =
      delete;
};

DECLARE_PUBLISHER(ProcessEventsPublisher);
} // namespace trailofbits
