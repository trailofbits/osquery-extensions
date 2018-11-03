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
#include "eventbufferlibrary.h"
#include "ieventpublisher.h"
#include "subscriberregistry.h"

#include <boost/thread/shared_mutex.hpp>

#include <memory>
#include <unordered_map>

#include <osquery/logger.h>

namespace trailofbits {
/// This is the base class used to build new publishers and provides somes
/// basic utilities to handle subscription and event handling
template <typename SubscriptionContext, typename EventContext>
class BaseEventPublisher : public IEventPublisher {
 public:
  /// The subscription context contains subscription-wide data
  using SubscriptionContextRef = std::shared_ptr<SubscriptionContext>;

  /// This type contains new events waiting to be processed
  using EventContextRef = std::shared_ptr<EventContext>;

 protected:
  /// The expected subscriber class type
  using SubscriberType = BaseEventSubscriber<
      BaseEventPublisher<SubscriptionContext, EventContext>>;

  /// A list of subscribers
  using SubscriberList =
      std::unordered_map<IEventSubscriberRef, SubscriptionContextRef>;

 private:
  /// The list of subscribers interested in the events emitted by this publisher
  SubscriberList subscriber_list;

  /// This mutex protects the subscriber map
  boost::shared_timed_mutex subscriber_map_mutex;

 public:
  /// Called each time the configuration changes (optional)
  virtual osquery::Status configure(
      const json11::Json& configuration) noexcept override {
    boost::upgrade_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);

    auto status = onConfigurationChangeStart(configuration);
    if (!status.ok()) {
      return status;
    }

    for (const auto& p : subscriber_list) {
      auto& subscriber_ref = p.first;
      auto& context_ref = p.second;

      auto subscriber_ptr = static_cast<SubscriberType*>(subscriber_ref.get());
      status = subscriber_ptr->configure(context_ref, configuration);
      if (!status.ok()) {
        LOG(ERROR) << "Subscriber returned error: " << status.getMessage();
      }

      status = onSubscriberConfigurationChange(
          configuration, *subscriber_ptr, context_ref);
      if (!status.ok()) {
        LOG(ERROR) << "Publisher returned error: " << status.getMessage();
        return status;
      }
    }

    return onConfigurationChangeEnd(configuration);
  }

  ///
  virtual osquery::Status onSubscriberConfigurationChange(
      const json11::Json& configuration,
      SubscriberType& subscriber,
      SubscriptionContextRef subscription_context) noexcept = 0;

  /// Utility function used by the actual publisher implementation to emit
  /// new events to all publishers
  osquery::Status updateSubscribers() noexcept override {
    boost::upgrade_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);

    for (const auto& p : subscriber_list) {
      auto& subscriber_ref = p.first;
      auto& context_ref = p.second;

      auto s = updateSubscriber(subscriber_ref, context_ref);
      if (!s.ok()) {
        return s;
      }
    }

    return osquery::Status(0);
  }

  virtual osquery::Status updateSubscriber(
      IEventSubscriberRef subscriber,
      SubscriptionContextRef subscription_context) noexcept = 0;

  /// This method is used by subscribers to register to new event data
  /// from this publisher
  virtual osquery::Status subscribe(IEventSubscriberRef subscriber) override {
    boost::unique_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);

    try {
      if (subscriber_list.count(subscriber) != 0U) {
        throw std::logic_error("Trying to register the same subscriber twice");
      }

      auto status = subscriber->initialize();
      if (!status.ok()) {
        return status;
      }

      auto subscription_context = std::make_shared<SubscriptionContext>();
      subscriber_list.insert({subscriber, subscription_context});
      return osquery::Status(0);

    } catch (const std::bad_alloc&) {
      return osquery::Status(1, "Memory allocation failure");
    }
  }

  /// This method unsubscribes the specified subscriber, and is typically
  /// used by the SubscriberRegistry class
  virtual void unsubscribe(IEventSubscriberRef subscriber) override {
    boost::unique_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);

    auto it = subscriber_list.find(subscriber);
    if (it == subscriber_list.end()) {
      throw std::logic_error("Trying to unregister a missing subscriber");
    }

    subscriber_list.erase(it);
    subscriber->release();
  }

  /// Returns the amount of active subscribers
  virtual std::size_t subscriptionCount() noexcept override {
    boost::upgrade_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);
    return subscriber_list.size();
  }

 protected:
  /// Utility function used by the actual publisher implementation to create
  /// a container for new events
  osquery::Status createEventContext(EventContextRef& event_context) const {
    try {
      event_context = std::make_shared<EventContext>();
      return osquery::Status(0);

    } catch (const std::bad_alloc&) {
      return osquery::Status(1, "Memory allocation failure");
    }
  }

  /// Utility function used by the actual publisher implementation to emit
  /// new events to all publishers
  void broadcastEvent(EventContextRef event_context) {
    boost::upgrade_lock<decltype(subscriber_map_mutex)> lock(
        subscriber_map_mutex);

    for (const auto& p : subscriber_list) {
      auto& subscriber_ref = p.first;
      auto& context_ref = p.second;

      auto subscriber_ptr = static_cast<SubscriberType*>(subscriber_ref.get());

      osquery::QueryData new_events = {};
      auto status =
          subscriber_ptr->callback(new_events, context_ref, event_context);

      if (!status.ok()) {
        LOG(ERROR) << "Subscriber returned error: " << status.getMessage();
      }

      if (!new_events.empty()) {
        auto buffer_name =
            SubscriberRegistry::instance().subscriberName(subscriber_ref);

        if (buffer_name.empty()) {
          LOG(ERROR) << "Failed to acquire the subscriber name";
          continue;
        }

        EventBufferLibrary::instance().saveEvents(new_events, buffer_name);
      }
    }
  }

  /// Utility function used by the actual publisher implementation to emit
  /// new events to all publishers
  void emitEvents(IEventSubscriberRef subscriber,
                  SubscriptionContextRef subscription_context,
                  EventContextRef event_context) {
    osquery::QueryData new_events = {};

    auto subscriber_ptr = static_cast<SubscriberType*>(subscriber.get());
    auto status = subscriber_ptr->callback(
        new_events, subscription_context, event_context);

    if (!status.ok()) {
      LOG(ERROR) << "Subscriber returned error: " << status.getMessage();
    }

    if (!new_events.empty()) {
      auto buffer_name =
          SubscriberRegistry::instance().subscriberName(subscriber);

      if (buffer_name.empty()) {
        LOG(ERROR) << "Failed to acquire the subscriber name";
      } else {
        EventBufferLibrary::instance().saveEvents(new_events, buffer_name);
      }
    }
  }
};

} // namespace trailofbits
