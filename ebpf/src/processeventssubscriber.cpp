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

#include "processeventssubscriber.h"

namespace trailofbits {
// clang-format off
BEGIN_TABLE(ebpf_process_events)
  TABLE_COLUMN(message, osquery::TEXT_TYPE)
END_TABLE(ebpf_process_events)
// clang-format on

struct ProcessEventsSubscriber::PrivateData final {};

ProcessEventsSubscriber::ProcessEventsSubscriber() : d(new PrivateData) {}

osquery::Status ProcessEventsSubscriber::create(
    IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new ProcessEventsSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ProcessEventsSubscriber::~ProcessEventsSubscriber() {}

osquery::Status ProcessEventsSubscriber::initialize() noexcept {
  return osquery::Status(0);
}

void ProcessEventsSubscriber::release() noexcept {}

osquery::Status ProcessEventsSubscriber::configure(
    ProcessEventsPublisher::SubscriptionContextRef,
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsSubscriber::callback(
    osquery::QueryData& new_data,
    ProcessEventsPublisher::SubscriptionContextRef,
    ProcessEventsPublisher::EventContextRef event_context) {
  new_data = {};

  for (const auto& str : event_context->string_list) {
    osquery::Row r = {};
    r["message"] = str;

    new_data.push_back(std::move(r));
  }

  return osquery::Status(0);
}
} // namespace trailofbits
