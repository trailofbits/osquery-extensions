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

#include <memory>
#include <trailofbits/ifirewall.h>

#ifdef _WIN32
#define CONFIGURATION_ROOT                                                     \
  "C:\\ProgramData\\osquery\\extensions\\com\\trailofbits\\fwctl"
#elif defined(__linux) || defined(__APPLE__)
#define CONFIGURATION_ROOT "/var/osquery/extensions/com/trailofbits/fwctl"
#endif

namespace trailofbits {
IFirewall& GetFirewall();
} // namespace trailofbits
