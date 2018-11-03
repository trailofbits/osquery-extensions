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

#include <atomic>
#include <memory>
#include <thread>

#include <osquery/sdk.h>
#include <osquery/status.h>

#include <json11.hpp>

namespace trailofbits {
class IService;

/// A reference to a service object
using IServiceRef = std::shared_ptr<IService>;

/// A reference to a std::thread object
using ThreadRef = std::shared_ptr<std::thread>;

/// This singleton is used to manage services
class ServiceManager final {
  /// True when the service manager is shutting down
  std::atomic_bool shutting_down{false};

  /// The list of services that have been created
  std::unordered_map<IServiceRef, ThreadRef> service_list;

  /// Service list mutex
  std::mutex service_list_mutex;

  /// Private constructor; use ::instance() instead
  ServiceManager();

 public:
  /// Returns an instance of the class
  static ServiceManager& instance();

  /// Destructor
  ~ServiceManager();

  /// Creates a new service
  template <typename T, typename... Args>
  osquery::Status createService(std::shared_ptr<T>& service_ref,
                                Args&&... args) {
    static_assert(std::is_base_of<IService, T>::value,
                  "The specified type is not a derived class of IService");

    service_ref.reset();

    if (shutting_down) {
      return osquery::Status(
          1, "Service creation failed: the service manager is shutting down");
    }

    std::lock_guard<std::mutex> lock(service_list_mutex);

    try {
      service_ref = std::make_shared<T>(std::forward<Args>(args)...);
      auto status = service_ref->initialize();
      if (!status) {
        return status;
      }

      auto thread_ref =
          std::make_shared<std::thread>(std::bind(&T::run, &(*service_ref)));

      service_list.insert({service_ref, thread_ref});
      return osquery::Status(0);

    } catch (const std::bad_alloc&) {
      if (service_ref) {
        service_ref->release();
      }

      return osquery::Status(1, "Memory allocation failure");
    }
  }

  /// Destroys the specified service
  void destroyService(IServiceRef service);

  /// Stops all services
  void stop();

  /// Disable the copy constructor
  ServiceManager(const ServiceManager& other) = delete;

  /// Disable the assignment operator
  ServiceManager& operator=(const ServiceManager& other) = delete;
};

/// Base class for services
class IService {
  /// True if the service should terminate
  std::atomic_bool terminate{false};

 protected:
  /// Tells this service that it should terminate as soon as possible
  void stop();

  /// Returns true if the service should terminate
  bool shouldTerminate() const;

 public:
  /// Constructor
  IService() = default;

  /// Destructor
  virtual ~IService() = default;

  /// Initialization callback; optional
  virtual osquery::Status initialize();

  /// Cleanup callback; optional
  virtual void release();

  /// This is the service entry point
  virtual void run() = 0;

  /// Disable the copy constructor
  IService(const IService& other) = delete;

  /// Disable the assignment operator
  IService& operator=(const IService& other) = delete;

  /// Allow the service manager to set the pointer to the termination flag
  friend class ServiceManager;
};
} // namespace trailofbits
