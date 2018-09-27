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

#include "ieventpublisher.h"

#include <atomic>
#include <memory>
#include <vector>

namespace trailofbits {
class PublisherScheduler;

/// A reference to a PublisherScheduler instance
using PublisherSchedulerRef = std::unique_ptr<PublisherScheduler>;

/// This class is responsible for allocating, configuring, running
/// and deinitializing all the registered event publishers
class PublisherScheduler final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::create() instead
  PublisherScheduler(std::vector<IEventPublisherRef> publisher_list);

 public:
  /// Creates a new instance of this class
  static osquery::Status create(
      PublisherSchedulerRef& publisher_scheduler,
      const std::vector<IEventPublisherRef>& publisher_list);

  /// Destructor
  ~PublisherScheduler();

  /// Starts the publisher threads
  osquery::Status start();

  /// Terminates the publishers
  void stop();

  /// Disable the copy constructor
  PublisherScheduler(const PublisherScheduler& other) = delete;

  /// Disable the assignment operator
  PublisherScheduler& operator=(const PublisherScheduler& other) = delete;
};
} // namespace trailofbits