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

#include "managedprobe.h"
#include <pubsub/servicemanager.h>

namespace trailofbits {
class ManagedProbeService final : public IService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  ManagedProbeService(ManagedProbe& probe);
  virtual ~ManagedProbeService() override;

  virtual osquery::Status initialize() override;
  virtual osquery::Status configure(const json11::Json& configuration);
  virtual void release() override;
  virtual void run() override;
};

using ManagedProbeServiceRef = std::shared_ptr<ManagedProbeService>;
} // namespace trailofbits
