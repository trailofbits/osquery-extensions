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

#include "processeventspublisher.h"
#include "ebpfeventsource.h"
#include "probes/common/defs.h"
#include "probes/kprobe_group/header.h"

#include <iomanip>
#include <iostream>

#include <asm/unistd_64.h>

namespace trailofbits {
struct ProcessEventsPublisher::PrivateData final {
  eBPFEventSourceRef event_source;
  ProbeEventList event_list;
  bool emit_fork_events{false};
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
    const json11::Json& configuration) noexcept {
  if (!configuration.is_object()) {
    return osquery::Status::failure("Invalid configuration");
  }

  const auto& emit_fork_events_obj = configuration["emit_fork_events"];
  if (emit_fork_events_obj == json11::Json()) {
    VLOG(1) << "The 'emit_fork_events' configuration setting is missing. "
               "Setting to false";
    d->emit_fork_events = false;

  } else {
    if (emit_fork_events_obj.is_bool()) {
      d->emit_fork_events = emit_fork_events_obj.bool_value();

    } else {
      VLOG(1) << "The 'emit_fork_events' value is not a bool. Setting to false";
      d->emit_fork_events = false;
    }
  }

  LOG(INFO) << "Fork events are now "
            << (d->emit_fork_events ? "shown" : "omitted");
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
  d->event_list = d->event_source->getEvents();
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::updateSubscriber(
    IEventSubscriberRef subscriber,
    SubscriptionContextRef subscription_context) noexcept {
  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  for (const auto& event : d->event_list) {
    bool is_fork_event = (event.function_identifier == KPROBE_FORK_CALL ||
                          event.function_identifier == KPROBE_VFORK_CALL ||
                          event.function_identifier == KPROBE_CLONE_CALL);

    if (is_fork_event && !d->emit_fork_events) {
      continue;
    }

    if (subscription_context->system_call_filter.count(
            event.function_identifier) == 0U) {
      continue;
    }

    event_context->probe_event_list.push_back(event);
  }

  if (!event_context->probe_event_list.empty()) {
    emitEvents(subscriber, subscription_context, event_context);
  }

  return osquery::Status(0);
}
} // namespace trailofbits
