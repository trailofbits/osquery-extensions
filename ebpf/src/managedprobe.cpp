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

#include "managedprobe.h"
#include "managed_probe_generator.h"
#include "probes/common/defs.h"

#include <condition_variable>
#include <mutex>

#include <osquery/logger.h>

namespace trailofbits {
struct ManagedProbe::PrivateData final {
  ManagedProbeDescriptor desc;
  eBPFProbeRef ebpf_probe;
};

ManagedProbe::ManagedProbe(const ManagedProbeDescriptor& desc)
    : d(new PrivateData) {
  d->desc = desc;

  std::string probe_source_code;
  auto status = generateManagedProbe(probe_source_code, desc);
  if (!status.ok()) {
    throw status;
  }

  eBPFProbeDescriptor probe_descriptor;
  probe_descriptor.name = desc.name;
  probe_descriptor.source_code = probe_source_code;

  probe_descriptor.callback = callbackDispatcher;
  probe_descriptor.callback_data = this;

  for (const auto& tracepoint : desc.tracepoint_list) {
    eBPFProbeDescriptor::Probe probe = {};
    probe.type = eBPFProbeDescriptor::Probe::Type::Tracepoint;
    probe.entry = (tracepoint.name.find("sys_enter_") != std::string::npos);
    probe.translate_name = true;
    probe.name = tracepoint.name;

    probe_descriptor.probe_list.push_back(std::move(probe));
  }

  status = eBPFProbe::create(d->ebpf_probe, probe_descriptor);
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status ManagedProbe::create(ManagedProbeRef& object,
                                     const ManagedProbeDescriptor& desc) {
  try {
    object.reset();

    auto ptr = new ManagedProbe(desc);
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ManagedProbe::~ManagedProbe() {}

std::ostream& operator<<(std::ostream& stream,
                         const SystemCallEvent& system_call_event) {
  static auto L_syscallName = [](std::uint64_t syscall_number) -> const char* {
    auto it = kSyscallNameTable.find(syscall_number);
    if (it == kSyscallNameTable.end()) {
      return "<UNKNOWN_SYSCALL_NAME>";
    }

    return it->second;
  };

  stream << std::setfill(' ') << std::setw(16) << system_call_event.timestamp
         << " ";

  stream << std::setfill(' ') << std::setw(8) << system_call_event.uid << " ";
  stream << std::setfill(' ') << std::setw(8) << system_call_event.gid << " ";
  stream << std::setfill(' ') << std::setw(8) << system_call_event.tgid << " ";
  stream << std::setfill(' ') << std::setw(8) << system_call_event.pid << " ";

  stream << std::setfill(' ') << std::setw(8)
         << system_call_event.syscall_number << " ";

  stream << std::setfill(' ') << std::setw(16)
         << L_syscallName(system_call_event.syscall_number) << "(";

  bool add_separator = false;
  for (const auto& field : system_call_event.field_list) {
    if (add_separator) {
      stream << ", ";
    }

    stream << field.first << "=";
    switch (field.second.which()) {
    case 0U: {
      const auto& value = boost::get<std::int64_t>(field.second);
      stream << value;
      break;
    }

    case 1U: {
      const auto& value = boost::get<std::uint64_t>(field.second);
      stream << value;
      break;
    }

    case 2U: {
      const auto& value = boost::get<std::string>(field.second);
      stream << "\"" << value << "\"";
      break;
    }

    case 3U: {
      const auto& value = boost::get<std::vector<std::uint8_t>>(field.second);
      stream << "{ " << value.size() << " bytes }";
      break;
    }

    case 4U: {
      const auto& value = boost::get<SystemCallEvent::StringList>(field.second);
      stream << "{";

      bool add_separator = false;
      for (const auto& s : value.data) {
        if (add_separator) {
          stream << ", ";
        }

        stream << "\"" << s << "\"";

        add_separator = true;
      }

      if (value.truncated) {
        if (add_separator) {
          stream << ", ";
        }

        stream << "...";
      }

      stream << "}";
      break;
    }
    }

    add_separator = true;
  }

  stream << ")";

  if (system_call_event.exit_code) {
    stream << " -> " << system_call_event.exit_code.get();
  }

  return stream;
}
} // namespace trailofbits
