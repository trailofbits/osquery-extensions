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
#include <unordered_map>

#include <osquery/status.h>

#include <BPF.h>

namespace trailofbits {
class eBPFProbe;
using eBPFProbeRef = std::unique_ptr<eBPFProbe>;

struct eBPFProbeDescriptor final {
  struct Probe final {
    enum class Type {
      Kprobe,
      Tracepoint,
    };

    Type type;
    bool entry{true};
    bool translate_name{false};
    std::string name;
  };

  std::string name;
  std::string source_code;

  std::vector<Probe> probe_list;
};

class eBPFProbe final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  osquery::Status attachProbes();
  void detachProbes();

  eBPFProbe(const eBPFProbeDescriptor& probe_descriptor);

 public:
  static osquery::Status create(eBPFProbeRef& object,
                                const eBPFProbeDescriptor& probe_descriptor);

  ~eBPFProbe();

  const eBPFProbeDescriptor& probeDescriptor() const;
  void poll();

  std::vector<std::uint32_t> getPerfEventData();
  ebpf::BPFPercpuArrayTable<std::uint64_t>& eventDataTable();

  eBPFProbe(const eBPFProbe&) = delete;
  eBPFProbe& operator=(const eBPFProbe&) = delete;

 private:
  static void eventCallbackDispatcher(void* callback_data,
                                      void* data,
                                      int data_size);

  void eventCallback(void* data, int data_size);
};
} // namespace trailofbits
