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

#include "configurationfile.h"

#include <osquery/status.h>

#include <memory>

namespace trailofbits {
/// Common base class for event subscribers
class IEventSubscriber {
 public:
  /// One-time initialization
  virtual osquery::Status initialize() noexcept = 0;

  /// One-time deinitialization
  virtual void release() noexcept = 0;

  /// Destructor
  virtual ~IEventSubscriber() = default;
};

/// A reference to an event subscriber
using IEventSubscriberRef = std::shared_ptr<IEventSubscriber>;
} // namespace trailofbits
