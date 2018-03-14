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

#include "globals.h"
#include "hostblacklist.h"
#include "portblacklist.h"

#include <iomanip>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>

namespace boostfs = boost::filesystem;
namespace boostsys = boost::system;

// We have to declare both namespaces or the REGISTER_EXTERNAL macro
// will not work correctly
using namespace osquery;
using namespace trailofbits;

REGISTER_EXTERNAL(HostBlacklistTable, "table", "HostBlacklist");
REGISTER_EXTERNAL(PortBlacklistTable, "table", "PortBlacklist");

bool Initialize() {
  auto status = trailofbits::CreateFirewallObject(firewall);
  if (!status.success()) {
    std::cerr << "Failed to create the firewall object\n";
    return false;
  }

  if (!boostfs::is_directory(CONFIGURATION_ROOT)) {
    boostsys::error_code error;
    boostfs::create_directories(CONFIGURATION_ROOT, error);
    if (error) {
      std::cerr << "Failed to create the configuration root folder: "
                << CONFIGURATION_ROOT << "\n";

      return false;
    }
  }

  return true;
}

int main(int argc, char* argv[]) {
  if (!Initialize()) {
    return 1;
  }

  Initializer runner(argc, argv, ToolType::EXTENSION);
  auto status = startExtension("Firewall", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();
  return 0;
}
