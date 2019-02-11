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
struct ProbeParameter final {
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

using ProbeParameterList = std::vector<ProbeParameter>;

struct ManagedTracepointDescriptor final {
  std::string name;
  bool entry{true};
  ProbeParameterList parameter_list;
};

struct ManagedTracepointProbe final {
  std::string name;

  std::size_t string_buffer_size{160U};
  std::size_t string_list_size{11U};

  std::vector<ManagedTracepointDescriptor> tracepoint_list;
};

using ManagedTracepointProbeList = std::vector<ManagedTracepointProbe>;

struct KprobeDescriptor final {
  std::string name;
  bool translate_name{false};
  bool entry{true};
  ProbeParameterList parameter_list;
};

struct KprobeProbe final {
  std::string name;
  std::string source_code;

  std::vector<KprobeDescriptor> kprobe_list;
};

using KprobeProbeList = std::vector<KprobeProbe>;

osquery::Status generateManagedTracepointProbe(
    eBPFProbeRef& probe, const ManagedTracepointProbe& desc);

osquery::Status generateKprobeProbe(eBPFProbeRef& probe,
                                    const KprobeProbe& desc);
} // namespace trailofbits
