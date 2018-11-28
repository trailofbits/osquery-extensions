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

#include "bccprocesseventsprogram.h"

#include <pubsub/servicemanager.h>

#include <memory>

namespace trailofbits {
/// This service pulls data from the eBPF probes
class BCCProcessEventsService final : public IService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  /// Constructor
  BCCProcessEventsService(std::size_t queue_count);

  /// Destructor
  virtual ~BCCProcessEventsService() override;

  /// Initialization callback; optional
  virtual osquery::Status initialize() override;

  /// Configuration change
  virtual osquery::Status configure(const json11::Json& configuration);

  /// Cleanup callback; optional
  virtual void release() override;

  /// This is the service entry point
  virtual void run() override;

  /// Returns a list of process events
  ProcessEventList getEvents(std::size_t slot);
};

/// A reference to a BCCProcessEventsService object
using BCCProcessEventsServiceRef = std::shared_ptr<BCCProcessEventsService>;
} // namespace trailofbits
