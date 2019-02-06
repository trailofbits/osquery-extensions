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

#include "ebpfprobe.h"

#include <cstdint>
#include <string>
#include <vector>

#include <osquery/logger.h>

namespace trailofbits {
struct ManagedTracepointDescriptor final {
  struct Parameter final {
    enum class Type {
      SignedInteger,
      UnsignedInteger,
      String,
      ByteArray,
      StringList
    };

    Type type{Type::SignedInteger};
    std::string name;
  };

  std::string name;
  std::vector<Parameter> parameter_list;
};

struct ManagedTracepointProbe final {
  std::string name;

  std::size_t string_buffer_size{160U};
  std::size_t string_list_size{11U};

  std::vector<ManagedTracepointDescriptor> tracepoint_list;
};

using ManagedTracepointProbeList = std::vector<ManagedTracepointProbe>;

osquery::Status generateManagedTracepointProbe(
    eBPFProbeRef& probe, const ManagedTracepointProbe& desc);
} // namespace trailofbits
