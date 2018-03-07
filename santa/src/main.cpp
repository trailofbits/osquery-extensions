/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <iostream>

#include "santa.h"
#include "extension.h"

int runAsStandalone() {
  LogEntries response;

  try {

    scrapeSantaLog(response);

  } catch (const std::exception& e) {
    std::cerr << "An error has occurred: " << e.what();
    return 1;
  }

  std::cout << "timestamp\t\tapplication\t\treason" << std::endl;
  for (LogEntries::const_iterator iter = response.begin(); iter != response.end(); ++iter) {
    std::cout << iter->timestamp << "\t\t" << iter->application << "\t\t" << iter->reason << std::endl;
  }
  return 0;
}

int runAsExtension(int argc, char* argv[]) {
  std::cout << "Connecting to the running osquery instance...\n";

  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

  auto status = osquery::startExtension("santa", "1.0.0");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();

  return 0;
}

void showUsage(char* argv[]) {
  const char* usage =
      " [--standalone]\n"
      "\n"
      "\t--standalone  Verify the system state and exit.\n"
      "\t              If not specified, it will run as an osquery extension\n";

  std::cerr << "Usage: " << argv[0] << usage;
}

int main(int argc, char* argv[]) {
  if (argc == 2 && std::strcmp(argv[1], "--standalone") == 0) {
    return runAsStandalone();

  } else if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
    showUsage(argv);
    return 0;

  } else {
    return runAsExtension(argc, argv);
  }
}
