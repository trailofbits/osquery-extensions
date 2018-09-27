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

#include "baseeventpublisher.h"

#include <memory>
#include <unordered_map>
#include <vector>

namespace trailofbits {
/// This is the type of the factory function that event publishers should
/// implement as a static method
using EventPublisherFactoryFunction =
    osquery::Status (*)(IEventPublisherRef& publisher);

/// The publisher registry, used to keep track all the event publishers that
/// have been declared
class PublisherRegistry final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructpr; use get() instead
  PublisherRegistry();

 public:
  /// Returns the name for the specified publisher
  std::string publisherName(IEventPublisherRef publisher);

  /// Destructor
  ~PublisherRegistry();

  /// Registers the given factory function for the specified publisher
  static osquery::Status declare(
      const std::string& name, EventPublisherFactoryFunction factory_function);

  /// Returns an instance of the PublisherRegistry
  static PublisherRegistry& instance();

  /// Returns the specified event publisher
  osquery::Status get(IEventPublisherRef& publisher, const std::string& name);

  // Releases the specified event publisher
  osquery::Status release(const std::string& name);

  /// Returns a list of active publishers
  std::vector<IEventPublisherRef> activePublishers();
};

// clang-format off
#define DECLARE_PUBLISHER(publisher_class) \
  namespace { \
    static auto publisher_manager_helper_ ## publisher_class = \
      PublisherRegistry::declare(publisher_class::name(), publisher_class::create); \
  }
// clang-format on
} // namespace trailofbits
