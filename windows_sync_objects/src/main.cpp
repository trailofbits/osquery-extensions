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

#include "windowssyncobjects.h"

#include <iomanip>
#include <iostream>

#include <osquery/logger.h>

// We have to declare both namespaces or the REGISTER_EXTERNAL macro
// will not work correctly
using namespace osquery;
using namespace trailofbits;

REGISTER_EXTERNAL(WindowsSyncObjectsTable, "table", "windows_sync_objects");

int main(int argc, char* argv[]) {
  Initializer runner(argc, argv, ToolType::EXTENSION);
  auto status = startExtension("windows_sync_objects", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();
  return 0;
}
