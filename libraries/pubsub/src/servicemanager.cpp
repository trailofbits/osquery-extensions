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

#include <pubsub/servicemanager.h>

#include <osquery/logger.h>

#include <vector>

namespace trailofbits {
ServiceManager::ServiceManager() {}

ServiceManager& ServiceManager::instance() {
  static ServiceManager obj;
  return obj;
}

ServiceManager::~ServiceManager() {}

void ServiceManager::destroyService(IServiceRef service) {
  std::lock_guard<std::mutex> lock(service_list_mutex);

  auto it = service_list.find(service);
  if (it == service_list.end()) {
    LOG(ERROR) << "Trying to stop a service that does not exist. Ignoring...";
    return;
  }

  auto& service_ref = it->first;
  service_ref->stop();

  auto& thread_ref = it->second;
  thread_ref->join();

  service_ref->release();

  service_list.erase(it);
}

void ServiceManager::stop() {
  std::lock_guard<std::mutex> lock(service_list_mutex);

  shutting_down = true;

  for (auto& p : service_list) {
    auto& service_ref = p.first;
    service_ref->stop();

    auto& thread_ref = p.second;
    thread_ref->join();

    service_ref->release();
  }

  service_list.clear();
}

void IService::stop() {
  terminate = true;
}

bool IService::shouldTerminate() const {
  return terminate.load();
}

osquery::Status IService::initialize() {
  return osquery::Status(0);
}

void IService::release() {}

} // namespace trailofbits
