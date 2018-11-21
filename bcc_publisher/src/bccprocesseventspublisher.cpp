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

#include "bccprocesseventspublisher.h"

namespace trailofbits {
struct BCCProcessEventsPublisher::PrivateData final {
  BCCProcessEventsProgramRef program;
};

BCCProcessEventsPublisher::BCCProcessEventsPublisher() : d(new PrivateData) {
  auto status = BCCProcessEventsProgram::create(d->program);
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status BCCProcessEventsPublisher::create(
    IEventPublisherRef& publisher) {
  try {
    auto ptr = new BCCProcessEventsPublisher();
    publisher.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsPublisher::initialize() noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::release() noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::onConfigurationChangeStart(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::onConfigurationChangeEnd(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::onSubscriberConfigurationChange(
    const json11::Json&, SubscriberType&, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::updatePublisher() noexcept {
  d->program->update();

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  event_context->event_list = d->program->getEvents();
  broadcastEvent(event_context);

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsPublisher::updateSubscriber(
    IEventSubscriberRef, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}
} // namespace trailofbits
