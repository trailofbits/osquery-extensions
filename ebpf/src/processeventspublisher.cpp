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

#include "processeventspublisher.h"
#include "ebpfeventsource.h"

namespace trailofbits {
struct ProcessEventsPublisher::PrivateData final {
  eBPFEventSourceRef event_source;
};

ProcessEventsPublisher::ProcessEventsPublisher() : d(new PrivateData) {
  auto status = eBPFEventSource::create(d->event_source);
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status ProcessEventsPublisher::create(IEventPublisherRef& publisher) {
  try {
    auto ptr = new ProcessEventsPublisher();
    publisher.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status ProcessEventsPublisher::initialize() noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::release() noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onConfigurationChangeStart(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onConfigurationChangeEnd(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onSubscriberConfigurationChange(
    const json11::Json&, SubscriberType&, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::updatePublisher() noexcept {
  auto new_events = d->event_source->getEvents();
  if (new_events.empty()) {
    return osquery::Status(0);
  }

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  std::stringstream buffer;
  for (const auto& event : new_events) {
    buffer.str("");
    buffer << event;

    event_context->string_list.push_back(buffer.str());
  }

  broadcastEvent(event_context);

  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::updateSubscriber(
    IEventSubscriberRef, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}
} // namespace trailofbits
