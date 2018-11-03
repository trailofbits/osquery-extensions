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

#include <pubsub/publisherregistry.h>
#include <pubsub/publisherscheduler.h>
#include <pubsub/subscriberregistry.h>

#include <atomic>
#include <thread>
#include <unordered_map>

#include <osquery/logger.h>

namespace trailofbits {
namespace {
/// A reference to a thread
using ThreadRef = std::unique_ptr<std::thread>;

/// Shared data between the scheduler and the publisher thread
struct PublisherThreadData final {
  /// Constructor, used to acquire the reference to the `terminate` flag
  PublisherThreadData(std::atomic_bool& terminate_thread)
      : terminate(terminate_thread) {}

  /// This thread
  ThreadRef thread;

  /// Whether the thread should terminate or keep processing data
  std::atomic_bool& terminate;

  /// The publisher that this thread should serve
  IEventPublisherRef publisher;

  /// The configuration file
  ConfigurationFileRef configuration_file;
};

/// A reference to a publisher thread
using PublisherThreadDataRef = std::shared_ptr<PublisherThreadData>;

/// A thread servicing a publisher
void publisherThread(PublisherThreadDataRef publisher_thread_data) {
  auto& terminate_thread = publisher_thread_data->terminate;
  auto configuration_file = publisher_thread_data->configuration_file;
  auto publisher_ref = publisher_thread_data->publisher;

  auto configuration_handle = configuration_file->getHandle();

  while (!terminate_thread) {
    if (configuration_file->configurationChanged(configuration_handle)) {
      auto configuration_data =
          configuration_file->getConfiguration(configuration_handle);

      auto s = publisher_ref->configure(configuration_data);
      if (!s.ok()) {
        auto publisher_name =
            PublisherRegistry::instance().publisherName(publisher_ref);

        LOG(ERROR) << "Publisher \"" << publisher_name
                   << "\" failed the configuration: " << s.getMessage()
                   << ". Halting...\n";
        break;
      }
    }

    auto s = publisher_ref->updatePublisher();
    if (!s.ok()) {
      auto publisher_name =
          PublisherRegistry::instance().publisherName(publisher_ref);

      LOG(ERROR) << "Publisher \"" << publisher_name
                 << "\" reported an error: " << s.getMessage()
                 << ". Halting...\n";
      break;
    }

    s = publisher_ref->updateSubscribers();
    if (!s.ok()) {
      auto publisher_name =
          PublisherRegistry::instance().publisherName(publisher_ref);

      LOG(ERROR) << "Publisher \"" << publisher_name
                 << "\" reported an error: " << s.getMessage()
                 << ". Halting...\n";
      break;
    }
  }
}
} // namespace

/// Private class data
struct PublisherScheduler::PrivateData final {
  /// The list of publishers allocated by the registries; it is used to spawn
  /// the threads that will make them run
  std::vector<IEventPublisherRef> publisher_list;

  /// The publisher thread list
  std::vector<PublisherThreadDataRef> publisher_thread_descriptors;

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

PublisherScheduler::~PublisherScheduler() {
  stop();
}

osquery::Status PublisherScheduler::start(
    ConfigurationFileRef configuration_file) {
  for (const auto& publisher : d->publisher_list) {
    try {
      auto publisher_thread_data =
          std::make_shared<PublisherThreadData>(d->terminate_threads);

      publisher_thread_data->publisher = publisher;
      publisher_thread_data->configuration_file = configuration_file;

      publisher_thread_data->thread =
          std::make_unique<std::thread>(publisherThread, publisher_thread_data);

      d->publisher_thread_descriptors.push_back(publisher_thread_data);

    } catch (const std::bad_alloc&) {
      return osquery::Status(1, "Memory allocation failure");
    }
  }

  if (d->publisher_thread_descriptors.empty()) {
    return osquery::Status(1, "No active publisher found");
  }

  return osquery::Status(0);
}
void PublisherScheduler::stop() {
  d->terminate_threads = true;

  for (const auto& publisher_descriptor : d->publisher_thread_descriptors) {
    publisher_descriptor->thread->join();
  }

  d->publisher_thread_descriptors.clear();
}
} // namespace trailofbits
