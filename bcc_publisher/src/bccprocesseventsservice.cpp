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
namespace {
using QueueList = std::vector<ProcessEventList>;
using MutexList = std::vector<std::mutex>;
using CVList = std::vector<std::condition_variable>;
} // namespace

struct BCCProcessEventsService::PrivateData final {
  BCCProcessEventsProgramRef program;

  QueueList queue_list;
  MutexList mutex_list;
  CVList cv_list;
};

BCCProcessEventsService::BCCProcessEventsService(std::size_t queue_count)
    : d(new PrivateData) {
  d->queue_list.resize(queue_count);
  d->mutex_list = MutexList(queue_count);
  d->cv_list = CVList(queue_count);
}

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
  while (!shouldTerminate()) {
    d->program->update();

    auto process_events = d->program->getEvents();
    if (process_events.empty()) {
      continue;
    }

    for (auto i = 0U; i < d->queue_list.size(); i++) {
      auto& queue = d->queue_list.at(i);
      auto& mutex = d->mutex_list.at(i);
      auto& cv = d->cv_list.at(i);

      {
        std::lock_guard<std::mutex> lock(mutex);
        queue.insert(queue.end(), process_events.begin(), process_events.end());
        cv.notify_all();
      }
    }
  }
}

ProcessEventList BCCProcessEventsService::getEvents(std::size_t slot) {
  auto& queue = d->queue_list.at(slot);
  auto& mutex = d->mutex_list.at(slot);
  auto& cv = d->cv_list.at(slot);

  ProcessEventList new_events;
  std::unique_lock<std::mutex> queue_lock(mutex);

  if (cv.wait_for(queue_lock, std::chrono::seconds(1)) ==
      std::cv_status::no_timeout) {
    new_events = std::move(queue);
    queue.clear();
  }

  return new_events;
}
} // namespace trailofbits
