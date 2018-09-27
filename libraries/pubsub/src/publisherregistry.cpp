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

#include "publisherregistry.h"

#include <boost/thread/shared_mutex.hpp>

namespace trailofbits {
namespace {
/// The map of allocated publishers
using PublisherMap = std::unordered_map<std::string, IEventPublisherRef>;

/// The internal registry of publisher factories
using PublisherFactoryMap =
    std::unordered_map<std::string, EventPublisherFactoryFunction>;

/// Accesser for the publisher factory map
PublisherFactoryMap& publisherFactoryMap() {
  static PublisherFactoryMap publisher_factory_map;
  return publisher_factory_map;
}
} // namespace

/// Private class data
struct PublisherRegistry::PrivateData final {
  /// The allocated publishers
  PublisherMap publisher_map;

  /// The mutex protecting the publisher map
  boost::shared_timed_mutex publisher_map_mutex;
};

PublisherRegistry::PublisherRegistry() : d(new PrivateData) {}

std::string PublisherRegistry::publisherName(IEventPublisherRef publisher) {
  boost::upgrade_lock<decltype(d->publisher_map_mutex)> read_lock(
      d->publisher_map_mutex);

  // clang-format off
  auto it = std::find_if(
    d->publisher_map.begin(),
    d->publisher_map.end(),

    [publisher](const PublisherMap::value_type &p) -> bool {
      return (publisher == p.second);
    }
  );
  // clang-format on

  if (it == d->publisher_map.end()) {
    return std::string();
  }

  return it->first;
}

PublisherRegistry::~PublisherRegistry() {
  assert(d->publisher_map.size() == 0U);
}

osquery::Status PublisherRegistry::declare(
    const std::string& name, EventPublisherFactoryFunction factory_function) {
  if (publisherFactoryMap().count(name) != 0U) {
    return osquery::Status(
        1, "Publisher \"" + name + "\" has already been registered");
  }

  publisherFactoryMap().insert({name, factory_function});
  return osquery::Status(0);
}

PublisherRegistry& PublisherRegistry::instance() {
  static PublisherRegistry instance;
  return instance;
}

osquery::Status PublisherRegistry::get(IEventPublisherRef& publisher,
                                       const std::string& name) {
  publisher.reset();

  boost::upgrade_lock<decltype(d->publisher_map_mutex)> read_lock(
      d->publisher_map_mutex);

  auto publisher_map_it = d->publisher_map.find(name);
  if (publisher_map_it != d->publisher_map.end()) {
    publisher = publisher_map_it->second;
    return osquery::Status(0);
  }

  auto pub_factory_map_it = publisherFactoryMap().find(name);
  if (pub_factory_map_it == publisherFactoryMap().end()) {
    return osquery::Status(1, "Publisher \"" + name + "\" is not registered");
  }

  boost::upgrade_to_unique_lock<decltype(d->publisher_map_mutex)>
      read_write_lock(read_lock);

  auto& factory_function = pub_factory_map_it->second;

  IEventPublisherRef publisher_obj;
  auto status = factory_function(publisher_obj);
  if (!status.ok()) {
    return status;
  }

  status = publisher_obj->initialize();
  if (!status.ok()) {
    return status;
  }

  d->publisher_map.insert({name, publisher_obj});
  publisher = publisher_obj;

  return osquery::Status(0);
}

osquery::Status PublisherRegistry::release(const std::string& name) {
  boost::unique_lock<decltype(d->publisher_map_mutex)> lock(
      d->publisher_map_mutex);

  IEventPublisherRef publisher;
  auto publisher_map_it = d->publisher_map.find(name);
  if (publisher_map_it == d->publisher_map.end()) {
    return osquery::Status(1, "Publisher \"" + name + "\" is not active");
  }

  publisher = publisher_map_it->second;
  if (publisher->subscriptionCount() > 0U) {
    return osquery::Status(
        false,
        "Publisher \"" + name +
            "\" can't be released because it still has active subscribers");
  }

  publisher->release();
  d->publisher_map.erase(name);

  return osquery::Status(0);
}

std::vector<IEventPublisherRef> PublisherRegistry::activePublishers() {
  boost::upgrade_lock<decltype(d->publisher_map_mutex)> read_lock(
      d->publisher_map_mutex);

  std::vector<IEventPublisherRef> output;
  for (const auto& p : d->publisher_map) {
    output.push_back(p.second);
  }

  return output;
}
} // namespace trailofbits