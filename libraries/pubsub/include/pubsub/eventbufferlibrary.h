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

#pragma once

#include <memory>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#include <osquery/sdk/sdk.h>
#pragma clang diagnostic pop
#include <osquery/extensions.h>

namespace trailofbits {
/// An event batch is just a list of rows that will get returned to osquery
/// during the ::generate() table callback
#if OSQUERY_VERSION_NUMBER < OSQUERY_SDK_VERSION(4, 0)
using EventBatch = std::vector<osquery::Row>;
#else
using EventBatch = std::vector<osquery::TableRowHolder>;
#endif


/// This singleton is used to create or acquire existing event buffers
class EventBufferLibrary final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::instance() instead
  EventBufferLibrary();

 public:
  /// Returns an instance of the class
  static EventBufferLibrary& instance();

  /// Destructor
  ~EventBufferLibrary();

  /// Saves the given events into the specified buffer
  void saveEvents(EventBatch& events, const std::string& buffer_name);

  /// Returns the events stored into the specifed buffer
  EventBatch getEvents(const std::string& buffer_name);

  /// Disable the copy constructor
  EventBufferLibrary(const EventBufferLibrary& other) = delete;

  /// Disable the assignment operator
  EventBufferLibrary& operator=(const EventBufferLibrary& other) = delete;
};
} // namespace trailofbits
