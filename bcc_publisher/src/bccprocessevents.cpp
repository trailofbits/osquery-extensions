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

#include "bccprocessevents.h"

namespace trailofbits {
// clang-format off
BEGIN_TABLE(ebpf_process_events)
  TABLE_COLUMN(type, osquery::TEXT_TYPE)
  TABLE_COLUMN(timestamp, osquery::TEXT_TYPE)
  TABLE_COLUMN(pid, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid_ns1, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid_ns2, osquery::TEXT_TYPE)
  TABLE_COLUMN(filename, osquery::TEXT_TYPE)
  TABLE_COLUMN(argv, osquery::TEXT_TYPE)
  TABLE_COLUMN(envp, osquery::TEXT_TYPE)
END_TABLE(ebpf_process_events)
// clang-format on

struct BCCProcessEvents::PrivateData final {};

BCCProcessEvents::BCCProcessEvents() : d(new PrivateData) {}

osquery::Status BCCProcessEvents::create(IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new BCCProcessEvents();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

BCCProcessEvents::~BCCProcessEvents() {}

osquery::Status BCCProcessEvents::initialize() noexcept {
  return osquery::Status(0);
}

void BCCProcessEvents::release() noexcept {}

osquery::Status BCCProcessEvents::configure(
    BCCProcessEventsPublisher::SubscriptionContextRef,
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEvents::callback(
    osquery::QueryData&,
    BCCProcessEventsPublisher::SubscriptionContextRef,
    BCCProcessEventsPublisher::EventContextRef) {
  return osquery::Status(0);
}
} // namespace trailofbits
