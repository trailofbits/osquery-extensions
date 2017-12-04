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

#include "efigy.h"
#include "extension.h"

#include <curl/curl.h>

#include <iomanip>
#include <iostream>

int runAsStandalone() {
  curl_global_init(CURL_GLOBAL_ALL);

  SystemInformation system_info;
  ServerResponse response;

  try {
    getSystemInformation(system_info);
    std::cout << "System details\n";
    std::cout << "  Board ID: " << system_info.board_id << "\n";
    std::cout << "  SMC version: " << system_info.smc_ver << "\n";
    std::cout << "  UUID: " << system_info.sys_uuid << "\n";
    std::cout << "  OS version: " << system_info.os_ver << "\n";
    std::cout << "  OS build: " << system_info.build_num << "\n";
    std::cout << "  EFI version: " << system_info.rom_ver << "\n";
    std::cout << "  Model: " << system_info.hw_ver << "\n";
    std::cout << "  MAC address: " << system_info.mac_addr << "\n\n";

    queryEFIgy(response, system_info);

  } catch (const std::exception& e) {
    std::cerr << "An error has occurred: " << e.what();
    return 1;
  }

  std::cout << "EFIgy output:\n";
  std::cout << std::setw(16) << "" << std::setw(20) << "Installed version"
            << std::setw(20) << "Latest version" << std::setw(20) << "Status\n";

  std::cout << std::setw(16) << "OS version" << std::setw(20)
            << system_info.os_ver << std::setw(20) << response.latest_os_version
            << std::setw(20)
            << (system_info.os_ver == response.latest_os_version ? "Up to date"
                                                                 : "Outdated")
            << "\n";

  std::cout << std::setw(16) << "OS build" << std::setw(20)
            << system_info.build_num << std::setw(20)
            << response.latest_build_number << std::setw(20)
            << (system_info.build_num == response.latest_build_number
                    ? "Up to date"
                    : "Outdated")
            << "\n";

  std::cout << std::setw(16) << "EFI version" << std::setw(20)
            << system_info.rom_ver << std::setw(20)
            << response.latest_efi_version << std::setw(20)
            << (system_info.rom_ver == response.latest_efi_version
                    ? "Up to date"
                    : "Outdated")
            << "\n";

  curl_global_cleanup();
  return 0;
}

int runAsExtension(int argc, char* argv[]) {
  std::cout << "Connecting to the running osquery instance...\n";

  curl_global_init(CURL_GLOBAL_ALL);
  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

  auto status = osquery::startExtension("efigy", "1.0.0");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();
  curl_global_cleanup();

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
