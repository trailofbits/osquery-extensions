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

#include "subscriberregistry.h"
#include "publisherregistry.h"

#include <boost/thread/shared_mutex.hpp>

#include <iostream>
#include <unordered_set>

namespace trailofbits {
namespace {
/// This structure holds the name of the publisher and the subscriber
struct EventSubscriberInformation final {
  std::string publisher_name;
  std::string subscriber_name;
};

/// Structure used to save the subscriber factory method inside the factory map
struct SubscriberFactoryDescriptor final {
  std::string publisher_name;
  EventSubscriberFactoryFunction factory_function;
};

/// The internal subscriber registry
using SubscriberFactoryMap =
    std::unordered_map<std::string, SubscriberFactoryDescriptor>;

/// The registry accesser
SubscriberFactoryMap& subscriberFactoryMap() {
  static SubscriberFactoryMap subscriber_factory_map;
  return subscriber_factory_map;
}
} // namespace

/// Private class data
struct SubscriberRegistry::PrivateData final {
  /// The subscriber map
  std::unordered_map<IEventSubscriberRef, EventSubscriberInformation>
      subscriber_map;

  /// The mutex protecting the subscriber map
  boost::shared_timed_mutex subscriber_map_mutex;
};

SubscriberRegistry::SubscriberRegistry() : d(new PrivateData) {}

std::string SubscriberRegistry::subscriberName(IEventSubscriberRef subscriber) {
  boost::upgrade_lock<decltype(d->subscriber_map_mutex)> lock(
      d->subscriber_map_mutex);

  auto it = d->subscriber_map.find(subscriber);
  if (it == d->subscriber_map.end()) {
    return std::string();
  }

  const auto& subscriber_info = it->second;
  return subscriber_info.subscriber_name;
}

SubscriberRegistry::~SubscriberRegistry() {}

osquery::Status SubscriberRegistry::declare(
    const std::string& publisher_name,
    const std::string& name,
    EventSubscriberFactoryFunction factory_function) {
  if (SubscriberFactoryMap().count(name) != 0U) {
    return osquery::Status(
        1, "Subscriber \"" + name + "\" has already been registered");
  }

  subscriberFactoryMap().insert({name, {publisher_name, factory_function}});
  return osquery::Status(0);
}

SubscriberRegistry& SubscriberRegistry::instance() {
  static SubscriberRegistry instance;
  return instance;
}

osquery::Status SubscriberRegistry::initialize() {
  boost::unique_lock<decltype(d->subscriber_map_mutex)> lock(
      d->subscriber_map_mutex);

  std::unordered_set<std::string> failed_publishers;

  for (const auto& p : subscriberFactoryMap()) {
    const auto& subscriber_name = p.first;
    const auto& subscriber_descriptor = p.second;

    if (failed_publishers.count(subscriber_descriptor.publisher_name) > 0U) {
      std::cerr << "Skipping subscriber \"" << subscriber_name
                << "\" because it depends on failed publisher \""
                << subscriber_descriptor.publisher_name << "\"\n";
      continue;
    }

    IEventSubscriberRef subscriber = {};
    auto status = subscriber_descriptor.factory_function(subscriber);
    if (!status.ok()) {
      std::cerr << "Failed to allocate subscriber \"" << subscriber_name
                << "\": " << status.getMessage() << "\n";
      continue;
    }

    IEventPublisherRef publisher = nullptr;
    status = PublisherRegistry::instance().get(
        publisher, subscriber_descriptor.publisher_name);

    if (!status.ok()) {
      std::cerr << "Failed to initialize publisher \""
                << subscriber_descriptor.publisher_name
                << "\": " << status.getMessage() << "\n";
      failed_publishers.insert(subscriber_descriptor.publisher_name);

      continue;
    }

    status = publisher->subscribe(subscriber);
    if (!status.ok()) {
      std::cerr << "Subscriber \"" << subscriber_name
                << "\" could not subscribe to publisher \""
                << subscriber_descriptor.publisher_name
                << "\": " << status.getMessage() << "\n";
    }

    d->subscriber_map.insert(
        {subscriber, {subscriber_name, subscriber_descriptor.publisher_name}});
  }

  if (d->subscriber_map.empty()) {
    return osquery::Status(1, "No active subscriber found");
  }

  return osquery::Status(0);
}

osquery::Status SubscriberRegistry::release() {
  boost::unique_lock<decltype(d->subscriber_map_mutex)> lock(
      d->subscriber_map_mutex);

  std::unordered_set<std::string> publisher_name_list;
  bool release_error = false;

  for (auto& p : d->subscriber_map) {
    auto subscriber_ref = p.first;
    const auto& subscriber_info = p.second;

    IEventPublisherRef publisher;
    auto status = PublisherRegistry::instance().get(
        publisher, subscriber_info.publisher_name);
    if (!status.ok()) {
      std::cerr << "Failed to acquire the following publisher: \""
                << subscriber_info.publisher_name << "\"\n";

      release_error = true;
      continue;
    }

    publisher->unsubscribe(subscriber_ref);
    publisher_name_list.insert(subscriber_info.publisher_name);
  }

  d->subscriber_map.clear();

  for (auto& publisher_name : publisher_name_list) {
    auto status = PublisherRegistry::instance().release(publisher_name);
    if (!status.ok()) {
      std::cerr << "Failed to release publisher \"" << publisher_name
                << "\": " << status.getMessage() << "\n";
      release_error = true;
    }
  }

  publisher_name_list.clear();

  if (release_error) {
    return osquery::Status(
        1, "One or more publishers could not be released correctly\n");
  }

  return osquery::Status(0);
}
} // namespace trailofbits