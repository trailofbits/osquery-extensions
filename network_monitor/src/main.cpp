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

#include "publisherregistry.h"
#include "publisherscheduler.h"
#include "subscriberregistry.h"

#include <osquery/sdk.h>

#include <iostream>

int main(int argc, char* argv[]) {
  auto status = trailofbits::SubscriberRegistry::instance().initialize();
  if (!status.ok()) {
    std::cerr << "Failed to initialize the publishers/subscribers: "
              << status.getMessage() << "\n";
    return 1;
  }

  auto active_publishers =
      trailofbits::PublisherRegistry::instance().activePublishers();

  trailofbits::PublisherSchedulerRef scheduler;
  status =
      trailofbits::PublisherScheduler::create(scheduler, active_publishers);
  if (!status.ok()) {
    std::cerr << "Failed to create the publisher scheduler: "
              << status.getMessage() << "\n";
    return 1;
  }

  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);
  status = osquery::startExtension("network_monitor", "1.0.0");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  status = scheduler->start();
  if (!status.ok()) {
    std::cerr << "The scheduler returned an error: " << status.getMessage()
              << "\n";
    return 1;
  }

  runner.waitForShutdown();

  scheduler->stop();
  scheduler.reset();

  status = trailofbits::SubscriberRegistry::instance().release();
  if (!status.ok()) {
    std::cerr << "Publishers/subscribers cleanup failed: "
              << status.getMessage() << "\n";
    return 1;
  }

  return 0;
}
