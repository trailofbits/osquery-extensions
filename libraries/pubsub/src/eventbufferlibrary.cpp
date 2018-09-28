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

#include <pubsub/eventbufferlibrary.h>

#include <iostream>

#include <boost/circular_buffer.hpp>
#include <boost/thread/shared_mutex.hpp>

namespace trailofbits {
namespace {
/// This is the maximum amount of rows that will be saved in each buffer
const std::size_t kCircularBufferSize = 4096U;

///
using CircularBuffer = boost::circular_buffer<osquery::Row>;

///
struct EventBuffer final {
  CircularBuffer data;
  std::mutex mutex;
};

///
using EventBufferRef = std::shared_ptr<EventBuffer>;

///
using EventBufferMap = std::unordered_map<std::string, EventBufferRef>;

///
EventBufferRef getEventBuffer(const std::string& buffer_name,
                              EventBufferMap& buffer_map,
                              boost::shared_timed_mutex& mutex) {
  boost::upgrade_lock<boost::shared_timed_mutex> read_lock(mutex);

  auto it = buffer_map.find(buffer_name);
  if (it != buffer_map.end()) {
    return it->second;
  }

  try {
    boost::upgrade_to_unique_lock<boost::shared_timed_mutex> read_write_lock(
        read_lock);

    auto event_buffer = std::make_shared<EventBuffer>();
    event_buffer->data.set_capacity(kCircularBufferSize);

    buffer_map.insert({buffer_name, event_buffer});
    return event_buffer;

  } catch (const std::bad_alloc&) {
    return EventBufferRef();
  }
}
} // namespace

/// Private class data
struct EventBufferLibrary::PrivateData final {
  EventBufferMap buffer_map;
  boost::shared_timed_mutex buffer_map_mutex;
};

EventBufferLibrary::EventBufferLibrary() : d(new PrivateData) {}

EventBufferLibrary& EventBufferLibrary::instance() {
  static EventBufferLibrary obj;
  return obj;
}

EventBufferLibrary::~EventBufferLibrary() {}

void EventBufferLibrary::saveEvents(EventBatch& events,
                                    const std::string& buffer_name) {
  auto event_buffer_ref =
      getEventBuffer(buffer_name, d->buffer_map, d->buffer_map_mutex);
  if (!event_buffer_ref) {
    std::cerr << "Failed to acquire the event buffer named \"" << buffer_name
              << "\"\n";
    return;
  }

  std::lock_guard<std::mutex> lock(event_buffer_ref->mutex);

  std::move(
      events.begin(), events.end(), std::back_inserter(event_buffer_ref->data));
  events.clear();
}

EventBatch EventBufferLibrary::getEvents(const std::string& buffer_name) {
  auto event_buffer_ref =
      getEventBuffer(buffer_name, d->buffer_map, d->buffer_map_mutex);
  if (!event_buffer_ref) {
    std::cerr << "Failed to acquire the event buffer named \"" << buffer_name
              << "\"\n";
    return {};
  }

  std::lock_guard<std::mutex> lock(event_buffer_ref->mutex);

  EventBatch event_batch;
  event_batch.reserve(event_buffer_ref->data.size());

  auto start = event_buffer_ref->data.begin();
  auto element_count = static_cast<int>(event_buffer_ref->data.size());
  auto end = std::next(start, element_count);

  std::move(start, end, std::back_inserter(event_batch));
  event_buffer_ref->data.clear();

  return event_batch;
}
} // namespace trailofbits
