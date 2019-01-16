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

#include "managedprobeservice.h"

namespace trailofbits {
struct ManagedProbeService::PrivateData final {
  ManagedProbe& probe;

  PrivateData(ManagedProbe& probe_) : probe(probe_) {}
};

ManagedProbeService::ManagedProbeService(ManagedProbe& probe)
    : d(new PrivateData(probe)) {}

ManagedProbeService::~ManagedProbeService() {}

osquery::Status ManagedProbeService::initialize() {
  return osquery::Status(0);
}

osquery::Status ManagedProbeService::configure(const json11::Json&) {
  return osquery::Status(0);
}

void ManagedProbeService::release() {}

void ManagedProbeService::run() {
  while (!shouldTerminate()) {
    d->probe.poll();
  }
}
} // namespace trailofbits
