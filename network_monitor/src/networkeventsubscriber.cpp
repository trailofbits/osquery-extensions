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

#include "networkeventsubscriber.h"

namespace trailofbits {
osquery::Status NetworkEventSubscriber::create(
    IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new NetworkEventSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status NetworkEventSubscriber::initialize() noexcept {
  std::cout << "Initializing NetworkEventSubscriber\n";
  return osquery::Status(0);
}

void NetworkEventSubscriber::release() noexcept {
  std::cout << "Releasing NetworkEventSubscriber\n";
}

osquery::Status NetworkEventSubscriber::configure() noexcept {
  std::cout << "Configuring NetworkEventSubscriber\n";
  return osquery::Status(0);
}

osquery::Status NetworkEventSubscriber::callback(
    NetworkEventPublisher::SubscriptionContextRef subscription_context,
    NetworkEventPublisher::EventContextRef event_context) {
  std::cout << "GOT EVENTS\n";
  return osquery::Status(0);
}
} // namespace trailofbits
