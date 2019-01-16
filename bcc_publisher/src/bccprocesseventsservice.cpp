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

#include "bccprocesseventsservice.h"

#include <condition_variable>
#include <vector>

namespace trailofbits {
struct BCCProcessEventsService::PrivateData final {
  BCCProcessEventsProgramRef program;

  ProcessEventList process_event_list;
  std::mutex process_event_list_mutex;
  std::condition_variable cv;
};

BCCProcessEventsService::BCCProcessEventsService() : d(new PrivateData) {}

BCCProcessEventsService::~BCCProcessEventsService() {}

osquery::Status BCCProcessEventsService::initialize() {
  auto status = BCCProcessEventsProgram::create(d->program);
  if (!status.ok()) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsService::configure(
    const json11::Json& configuration) {
  static_cast<void>(configuration);
  return osquery::Status(0);
}

void BCCProcessEventsService::release() {}

void BCCProcessEventsService::run() {
  d->program->initialize();

  while (!shouldTerminate()) {
    auto process_events = d->program->getEvents();
    if (!process_events.empty()) {
      std::lock_guard<std::mutex> lock(d->process_event_list_mutex);

      d->process_event_list.insert(process_events.begin(),
                                   process_events.end());
      d->cv.notify_all();
    }
  }
}

ProcessEventList BCCProcessEventsService::getEvents() {
  ProcessEventList new_events;
  std::unique_lock<std::mutex> lock(d->process_event_list_mutex);

  if (d->cv.wait_for(lock, std::chrono::seconds(1)) ==
      std::cv_status::no_timeout) {
    new_events = std::move(d->process_event_list);
    d->process_event_list.clear();
  }

  return new_events;
}
} // namespace trailofbits
