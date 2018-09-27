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

#include "baseeventsubscriber.h"

#include <memory>
#include <unordered_map>
#include <vector>

namespace trailofbits {
/// This is the type of the factory function that event subscribers should
/// implement as a static method
using EventSubscriberFactoryFunction =
    osquery::Status (*)(IEventSubscriberRef& subscriber);

/// The subscriber registry, used to keep track all the event subscribers that
/// have been declared
class SubscriberRegistry final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use get() instead
  SubscriberRegistry();

 public:
  /// Returns the name for the specified subscriber
  std::string subscriberName(IEventSubscriberRef subscriber);

  /// Destructor
  ~SubscriberRegistry();

  /// Registers the given factory function for the specified subscriber
  static osquery::Status declare(
      const std::string& publisher_name,
      const std::string& name,
      EventSubscriberFactoryFunction factory_function);

  /// Returns an instance of the SubscriberRegistry
  static SubscriberRegistry& instance();

  /// Initializes all subscribers and the required publishers
  osquery::Status initialize();

  /// Releases all subscribers and associated publishers
  osquery::Status release();
};

// clang-format off
#define DECLARE_SUBSCRIBER(publisher_class, subscriber_class) \
  namespace { \
    static auto subscriber_manager_helper_ ## subscriber_class = \
      SubscriberRegistry::declare(publisher_class::name(), subscriber_class::name(), subscriber_class::create); \
  }
// clang-format on
} // namespace trailofbits
