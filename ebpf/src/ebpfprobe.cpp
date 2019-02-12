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

#include "ebpfprobe.h"

#include <osquery/logger.h>

namespace trailofbits {
namespace {
const int kPollTime{1000};

using BPFRef = std::unique_ptr<ebpf::BPF>;

void getProbeEventName(std::string& event_name,
                       const eBPFProbeDescriptor::Probe& probe) {
  event_name = {};

  if (probe.type == eBPFProbeDescriptor::Probe::Type::Kprobe) {
    if (probe.translate_name) {
      ebpf::BPF bpf;
      event_name = bpf.get_syscall_fnname(probe.name);
    } else {
      event_name = probe.name;
    }

  } else {
    if (probe.translate_name) {
      event_name = "syscalls:";
    }

    event_name += probe.name;
  }
}

void getProbeEventHandlerName(std::string& handler_name,
                              const eBPFProbeDescriptor::Probe& probe) {
  handler_name = {};

  if (probe.type == eBPFProbeDescriptor::Probe::Type::Kprobe) {
    handler_name = std::string("kprobe_") + probe.name;
    if (probe.entry) {
      handler_name += "_enter";
    } else {
      handler_name += "_exit";
    }

  } else {
    handler_name = std::string("tracepoint_") + probe.name;
  }
}
} // namespace

struct eBPFProbe::PrivateData final {
  eBPFProbeDescriptor probe_descriptor;

  BPFRef bpf;
  ebpf::BPFPercpuArrayTable<std::uint64_t> event_data_table;

  ebpf::BPFPerfBuffer* perf_event_buffer{nullptr};

  std::unordered_map<std::string, int> attached_kprobe_list;
  std::vector<std::string> attached_tracepoint_list;

  std::vector<std::uint32_t> perf_event_data;
  std::mutex perf_event_data_mutex;
  std::condition_variable perf_event_data_cv;

  PrivateData(BPFRef bpf_,
              ebpf::BPFPercpuArrayTable<std::uint64_t> event_data_table_)
      : bpf(std::move(bpf_)), event_data_table(std::move(event_data_table_)) {}
};

eBPFProbe::eBPFProbe(const eBPFProbeDescriptor& probe_descriptor) {
  auto bpf = std::make_unique<ebpf::BPF>();
  auto bpf_status = bpf->init(probe_descriptor.source_code);
  if (bpf_status.code() != 0) {
    throw osquery::Status::failure("eBPF initialization error: " +
                                   bpf_status.msg());
  }

  static auto L_lostEventCallback = [](void* user_defined,
                                       std::uint64_t count) -> void {
    auto& ebpf_probe = *reinterpret_cast<eBPFProbe*>(user_defined);

    const auto& probe_name = ebpf_probe.probeDescriptor().name;
    LOG(ERROR) << "Probe '" << probe_name << "' has lost " << count
               << " events";
  };

  bpf_status = bpf->open_perf_buffer(
      "events", &eBPFProbe::eventCallbackDispatcher, L_lostEventCallback, this);

  if (bpf_status.code() != 0) {
    throw osquery::Status::failure("eBPF initialization error: " +
                                   bpf_status.msg());
  }

  auto event_data_table =
      bpf->get_percpu_array_table<std::uint64_t>("perf_event_data");

  d = std::make_unique<PrivateData>(std::move(bpf),
                                    std::move(event_data_table));
  bpf.release();

  d->probe_descriptor = probe_descriptor;
  d->perf_event_buffer = d->bpf->get_perf_buffer("events");

  auto status = attachProbes();
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status eBPFProbe::create(eBPFProbeRef& object,
                                  const eBPFProbeDescriptor& probe_descriptor) {
  try {
    object.reset();

    auto ptr = new eBPFProbe(probe_descriptor);
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

eBPFProbe::~eBPFProbe() {
  detachProbes();
}

const eBPFProbeDescriptor& eBPFProbe::probeDescriptor() const {
  return d->probe_descriptor;
}

void eBPFProbe::poll() {
  d->perf_event_buffer->poll(kPollTime);
}

std::vector<std::uint32_t> eBPFProbe::getPerfEventData() {
  std::vector<std::uint32_t> perf_event_data;

  std::unique_lock<std::mutex> lock(d->perf_event_data_mutex);

  if (d->perf_event_data_cv.wait_for(lock, std::chrono::seconds(1)) ==
      std::cv_status::no_timeout) {
    perf_event_data = std::move(d->perf_event_data);
    d->perf_event_data.clear();
  }

  return perf_event_data;
}

ebpf::BPFPercpuArrayTable<std::uint64_t>& eBPFProbe::eventDataTable() {
  return d->event_data_table;
}

void eBPFProbe::eventCallbackDispatcher(void* callback_data,
                                        void* data,
                                        int data_size) {
  auto& this_obj = *reinterpret_cast<eBPFProbe*>(callback_data);
  this_obj.eventCallback(data, data_size);
}

void eBPFProbe::eventCallback(void* data, int data_size) {
  if ((data_size % 4) != 0) {
    LOG(ERROR) << "Invalid data size";
    return;
  }

  {
    std::lock_guard<std::mutex> lock(d->perf_event_data_mutex);

    auto perf_event_data_ptr = reinterpret_cast<const std::uint32_t*>(data);
    for (auto i = 0; i < (data_size / 4); i++) {
      d->perf_event_data.push_back(perf_event_data_ptr[i]);
    }
  }

  d->perf_event_data_cv.notify_one();
}

osquery::Status eBPFProbe::attachProbes() {
  for (const auto& probe : d->probe_descriptor.probe_list) {
    std::string event_name;
    getProbeEventName(event_name, probe);

    std::string handler_name;
    getProbeEventHandlerName(handler_name, probe);

    if (probe.type == eBPFProbeDescriptor::Probe::Type::Kprobe) {
      auto bpf_probe_type = probe.entry ? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;

      auto bpf_status =
          d->bpf->attach_kprobe(event_name, handler_name, 0, bpf_probe_type);

      if (bpf_status.code() != 0) {
        return osquery::Status::failure(
            "Failed to attach the following kprobe: " + event_name + "/" +
            handler_name + ". Error: " + bpf_status.msg());
      }

      d->attached_kprobe_list.insert({event_name, bpf_probe_type});

    } else {
      auto bpf_status = d->bpf->attach_tracepoint(event_name, handler_name);
      if (bpf_status.code() != 0) {
        return osquery::Status::failure(
            "Failed to attach the following tracepoint: " + event_name + "/" +
            handler_name + ". Error: " + bpf_status.msg());
      }

      d->attached_tracepoint_list.push_back(event_name);
    }
  }

  return osquery::Status(0);
}

void eBPFProbe::detachProbes() {
  for (const auto& p : d->attached_kprobe_list) {
    const auto& name = p.first;
    const auto& type = p.second;

    auto bpf_status =
        d->bpf->detach_kprobe(name, static_cast<bpf_probe_attach_type>(type));
    if (bpf_status.code() != 0) {
      LOG(ERROR) << "Failed to detach the following kprobe: " << name
                 << (type == BPF_PROBE_ENTRY ? " (entry)" : " (return)")
                 << ". Error: " << bpf_status.msg();
    }
  }

  d->attached_kprobe_list.clear();

  for (const auto& tracepoint : d->attached_tracepoint_list) {
    auto bpf_status = d->bpf->detach_tracepoint(tracepoint);
    if (bpf_status.code() != 0) {
      LOG(ERROR) << "Failed to detach the following tracepoint: " << tracepoint
                 << ". Error: " << bpf_status.msg();
    }
  }

  d->attached_tracepoint_list.clear();
}
} // namespace trailofbits
