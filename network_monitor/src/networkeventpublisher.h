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

#include "publisherregistry.h"

#include <memory>
#include <string>

namespace trailofbits {
class NetworkEventPublisher;

/// A reference to a NetworkEventPublisher object
struct NetworkEventSubscriptionContext final {};

struct NetworkEventData final {};

/// A network sniffer based on libcap
class NetworkEventPublisher final
    : public BaseEventPublisher<NetworkEventSubscriptionContext,
                                NetworkEventData> {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use the ::create() static function instead
  explicit NetworkEventPublisher();

 public:
  /// Factory function used to create NetworkEventPublisher objects
  static osquery::Status create(IEventPublisherRef& publisher);

  /// Returns the friendly publisher name
  static const char* name() {
    return "network_events";
  }

  /// Destructor
  virtual ~NetworkEventPublisher() = default;

  /// One-time initialization
  osquery::Status initialize() noexcept override;

  /// One-time deinitialization
  osquery::Status release() noexcept override;

  /// Called each time the configuration changes
  osquery::Status configure() noexcept override;

  /// Worker method; should perform some work and then return
  osquery::Status run() noexcept override;

  /// Disable the copy constructor
  NetworkEventPublisher(const NetworkEventPublisher& other) = delete;

  /// Disable the assignment operator
  NetworkEventPublisher& operator=(const NetworkEventPublisher& other) = delete;
};

DECLARE_PUBLISHER(NetworkEventPublisher);
} // namespace trailofbits
