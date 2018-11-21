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

void ServiceManager::stop() {
  std::lock_guard<std::mutex> lock(service_list_mutex);

  terminate = true;

  for (auto& service_descriptor : service_list) {
    service_descriptor.thread_ref->join();
    service_descriptor.service_ref->release();
  }

  service_list.clear();
}

bool IService::shouldTerminate() const {
  assert(terminate != nullptr && "IService::terminate set to nullptr");
  return terminate->load();
}

osquery::Status IService::initialize() {
  return osquery::Status(0);
}

void IService::release() {}

} // namespace trailofbits
