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

#include "publisherscheduler.h"
#include "publisherregistry.h"
#include "subscriberregistry.h"

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_map>

namespace trailofbits {
/// Private class data
struct PublisherScheduler::PrivateData final {
  /// The list of publishers allocated by the registries; it is used to spawn
  /// the threads that will make them run
  std::vector<IEventPublisherRef> publisher_list;

  /// The list of publisher threads
  std::vector<std::unique_ptr<std::thread>> publisher_thread_list;

  /// This is used to send the shutdown command to the threads
  std::atomic_bool terminate_threads{false};
};

PublisherScheduler::PublisherScheduler(
    std::vector<IEventPublisherRef> publisher_list)
    : d(new PrivateData) {
  d->publisher_list = std::move(publisher_list);
}

osquery::Status PublisherScheduler::create(
    PublisherSchedulerRef& publisher_scheduler,
    const std::vector<IEventPublisherRef>& publisher_list) {
  publisher_scheduler.reset();

  try {
    auto ptr = new PublisherScheduler(publisher_list);
    publisher_scheduler.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

PublisherScheduler::~PublisherScheduler() {}

osquery::Status PublisherScheduler::start() {
  for (const auto& publisher : d->publisher_list) {
    auto status = publisher->configure();
    if (!status.ok()) {
      auto publisher_name =
          PublisherRegistry::instance().publisherName(publisher);

      std::cerr << "Publisher \"" << publisher_name
                << "\" failed to update the configuration: "
                << status.getMessage() << "\n";

      continue;
    }

    try {
      auto& terminate = d->terminate_threads;

      // clang-format off
      auto thread_ref = std::make_unique<std::thread>([&publisher, &terminate]() -> void {
        while (!terminate) {
          // todo: check and update configuration
          // ...

          auto s = publisher->run();
          if (!s.ok()) {
            auto publisher_name =
                PublisherRegistry::instance().publisherName(publisher);
            std::cerr << "Publisher \"" << publisher_name
                      << "\" reported an error: " << s.getMessage()
                      << ". Halting...\n";
            break;
          }
        }
      });
      // clang-format on

      d->publisher_thread_list.push_back(std::move(thread_ref));

    } catch (const std::bad_alloc&) {
      return osquery::Status(1, "Memory allocation failure");
    }
  }

  if (d->publisher_thread_list.empty()) {
    return osquery::Status(1, "No active publisher found");
  }

  return osquery::Status(0);
}
void PublisherScheduler::stop() {
  d->terminate_threads = true;

  for (const auto& publisher_thread : d->publisher_thread_list) {
    publisher_thread->join();
  }

  d->publisher_thread_list.clear();
}
} // namespace trailofbits
