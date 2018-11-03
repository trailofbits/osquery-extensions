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

#include <pubsub/publisherregistry.h>
#include <pubsub/publisherscheduler.h>
#include <pubsub/servicemanager.h>
#include <pubsub/subscriberregistry.h>

#include <osquery/database.h>
#include <osquery/dispatcher.h>
#include <osquery/events.h>
#include <osquery/sdk.h>

#include <sys/resource.h>
#include <sys/time.h>

#include <iostream>

const std::string kConfigurationFile =
    "/var/osquery/extensions/com/trailofbits/bcc_publisher.json";

static void enforce_infinite_rlimit() {
  struct rlimit rl = {};
  if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
    std::cerr << "Warning: couldn't set RLIMIT for BCC. "
              << "If your program is not loading, you can try "
              << "\"ulimit -l 8192\" to fix the problem" << std::endl;
    return;
  }
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;
  if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0)
    std::cerr << "Warning: couldn't set RLIMIT for BCC. "
              << "If your program is not loading, you can try "
              << "\"ulimit -l 8192\" to fix the problem" << std::endl;
}

int main(int argc, char* argv[]) {
  enforce_infinite_rlimit();

  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

  auto status = osquery::startExtension("bcc_publisher", "1.0.0");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  status = trailofbits::SubscriberRegistry::instance().initialize();
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

  trailofbits::ConfigurationFileRef configuration_file;
  status = trailofbits::ConfigurationFile::create(configuration_file,
                                                  kConfigurationFile);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return 1;
  }

  status = scheduler->start(configuration_file);
  if (!status.ok()) {
    std::cerr << "The scheduler returned an error: " << status.getMessage()
              << "\n";
    return 1;
  }

  // We can't use the runner.waitForShutdown() method because it calls exit()
  osquery::Dispatcher::joinServices();
  osquery::EventFactory::end(true);
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
  osquery::DatabasePlugin::shutdown();

  scheduler->stop();
  scheduler.reset();

  status = trailofbits::SubscriberRegistry::instance().release();
  if (!status.ok()) {
    LOG(ERROR) << "Publishers/subscribers cleanup failed: "
               << status.getMessage() << "\n";
  }

  trailofbits::ServiceManager::instance().stop();
  return 0;
}
