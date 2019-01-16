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
#include <iomanip>
#include <iostream>
#include <mutex>

#include <osquery/logger.h>

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
bool readEventSlot(std::vector<std::uint64_t>& table_data,
                   int& index,
                   std::size_t cpu_id,
                   ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table) {
  table_data.clear();

  auto status = event_data_table.get_value(index, table_data);
  if (status.code() != 0) {
    LOG(ERROR) << "Read has failed: " << status.msg();
    return false;
  }

  if (cpu_id >= table_data.size()) {
    LOG(ERROR) << "Invalid CPU index: " << cpu_id;
    return false;
  }

  INCREMENT_EVENT_DATA_INDEX(index);
  return true;
}

template <typename T>
bool readEventData(T& value,
                   std::vector<std::uint64_t>& table_data,
                   int& index,
                   std::size_t cpu_id,
                   ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table) {
  value = {};

  if (!readEventSlot(table_data, index, cpu_id, event_data_table)) {
    return false;
  }

  value = static_cast<T>(table_data[cpu_id]);
  return true;
}

bool readEventString(std::string& value,
                     std::vector<std::uint64_t>& table_data,
                     int& index,
                     std::size_t cpu_id,
                     ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
                     std::size_t string_buffer_size) {
  value.clear();

  union {
    std::uint64_t string_chunk;
    char string_chunk_bytes[8U];
  };

  std::size_t i = 0U;
  bool terminate = false;
  auto chunk_count = (string_buffer_size / 8U);

  for (i = 0U; i < chunk_count && !terminate; ++i) {
    string_chunk = 0U;
    if (!readEventData(
            string_chunk, table_data, index, cpu_id, event_data_table)) {
      return false;
    }

    value.reserve(value.size() + 8U);
    for (auto k = 0U; k < sizeof(string_chunk_bytes); k++) {
      if (string_chunk_bytes[k] == 0) {
        terminate = true;
        break;
      }

      value.push_back(string_chunk_bytes[k]);
    }
  }

  auto skipped_slots = chunk_count - i;
  INCREMENT_EVENT_DATA_INDEX_BY(index, skipped_slots);

  return true;
}

bool readEventStringList(
    SystemCallEvent::StringList& value,
    std::vector<std::uint64_t>& table_data,
    int& index,
    std::size_t cpu_id,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t string_buffer_size,
    std::size_t string_list_size) {
  value = {};

  for (std::size_t string_index = 0U; string_index < string_list_size;
       string_index++) {
    std::uint64_t next_qword;
    auto temp_index = index;
    if (!readEventData(
            next_qword, table_data, temp_index, cpu_id, event_data_table)) {
      return false;
    }

    if (next_qword == VARARGS_TRUNCATION) {
      value.truncated = true;
      index = temp_index;
      break;

    } else if (next_qword == VARARGS_TERMINATOR) {
      value.truncated = false;
      index = temp_index;
      break;
    }

    std::string str = {};
    if (!readEventString(str,
                         table_data,
                         index,
                         cpu_id,
                         event_data_table,
                         string_buffer_size)) {
      return false;
    }

    value.data.push_back(std::move(str));
  }

  return true;
} // namespace
} // namespace

struct ManagedProbe::PrivateData final {
  ManagedProbeDescriptor desc;
  eBPFProbeRef ebpf_probe;

  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;
  SystemCallEventList event_list;
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

void ManagedProbe::callbackDispatcher(void* callback_data,
                                      void* data,
                                      int data_size) {
  auto& this_ptr = *static_cast<ManagedProbe*>(callback_data);

  if ((data_size % 4) != 0) {
    LOG(ERROR) << "Invalid data size";
    return;
  }

  this_ptr.callback(static_cast<const std::uint32_t*>(data),
                    static_cast<std::size_t>(data_size / 4));
}

void ManagedProbe::callback(const std::uint32_t* data, std::size_t data_size) {
  auto event_data_table = d->ebpf_probe->eventDataTable();

  SystemCallEventList new_event_list;

  auto tracepoint_list_size = d->desc.tracepoint_list.size();

  for (auto i = 0U; i < data_size; i++) {
    auto event_identifier = data[i];

    int index =
        static_cast<int>(event_identifier & 0x00FFFFFF) % EVENT_MAP_SIZE;

    auto cpu_id =
        static_cast<std::size_t>((event_identifier >> 28) & 0x000000FF);

    std::vector<std::uint64_t> table_data;

    std::uint64_t event_type;
    if (!readEventData(
            event_type, table_data, index, cpu_id, event_data_table)) {
      continue;
    }

    if ((event_type & 0xFFFFFFFFFFFF0000ULL) != 0x1122334455660000ULL) {
      LOG(ERROR) << "Broken event type: " << std::hex << event_type
                 << " from the following tracepoint: " << d->desc.name;
      continue;
    }

    event_type &= 0xFFFF;

    if (event_type >= tracepoint_list_size) {
      LOG(ERROR) << "Invalid event type: " << std::hex << event_type
                 << " from the following tracepoint: " << d->desc.name;
      continue;
    }

    const auto& tracepoint_desc = d->desc.tracepoint_list.at(event_type);

    // Read the header
    SystemCallEvent system_call_event = {};
    if (!readEventData(system_call_event.syscall_number,
                       table_data,
                       index,
                       cpu_id,
                       event_data_table)) {
      continue;
    }

    if (!readEventData(system_call_event.timestamp,
                       table_data,
                       index,
                       cpu_id,
                       event_data_table)) {
      continue;
    }

    std::uint64_t pid_tgid;
    if (!readEventData(pid_tgid, table_data, index, cpu_id, event_data_table)) {
      continue;
    }

    system_call_event.pid = static_cast<pid_t>(pid_tgid & 0xFFFFFFFF);
    system_call_event.tgid = static_cast<pid_t>(pid_tgid >> 32U);

    std::uint64_t uid_gid;
    if (!readEventData(uid_gid, table_data, index, cpu_id, event_data_table)) {
      continue;
    }

    system_call_event.uid = static_cast<uid_t>(uid_gid & 0xFFFFFFFF);
    system_call_event.gid = static_cast<gid_t>(uid_gid >> 32U);

    /// TODO(alessandro): cache this
    if (tracepoint_desc.name.find("sys_exit_") != std::string::npos) {
      int exit_code;
      if (!readEventData(
              exit_code, table_data, index, cpu_id, event_data_table)) {
        continue;
      }

      system_call_event.exit_code = exit_code;
    }

    bool parameter_read_error = false;

    for (const auto& parameter : tracepoint_desc.parameter_list) {
      if (parameter.type == ManagedProbeTracepoint::Parameter::Type::String) {
        std::string value;
        if (!readEventString(value,
                             table_data,
                             index,
                             cpu_id,
                             event_data_table,
                             d->desc.string_buffer_size)) {
          parameter_read_error = true;
          break;
        }

        system_call_event.field_list.insert({parameter.name, value});

      } else if (parameter.type ==
                 ManagedProbeTracepoint::Parameter::Type::SignedInteger) {
        std::int64_t value;
        if (!readEventData(
                value, table_data, index, cpu_id, event_data_table)) {
          parameter_read_error = true;
          break;
        }

        system_call_event.field_list.insert({parameter.name, value});

      } else if (parameter.type ==
                 ManagedProbeTracepoint::Parameter::Type::UnsignedInteger) {
        std::uint64_t value;
        if (!readEventData(
                value, table_data, index, cpu_id, event_data_table)) {
          parameter_read_error = true;
          break;
        }

        system_call_event.field_list.insert({parameter.name, value});

      } else if (parameter.type ==
                 ManagedProbeTracepoint::Parameter::Type::StringList) {
        SystemCallEvent::StringList value;
        if (!readEventStringList(value,
                                 table_data,
                                 index,
                                 cpu_id,
                                 event_data_table,
                                 d->desc.string_buffer_size,
                                 d->desc.string_list_size)) {
          parameter_read_error = true;
          break;
        }

        system_call_event.field_list.insert({parameter.name, value});

      } else {
        LOG(ERROR) << "Invalid parameter from the following tracepoint: "
                   << d->desc.name;

        parameter_read_error = true;
        break;
      }
    }

    if (parameter_read_error) {
      continue;
    }

    new_event_list.push_back(std::move(system_call_event));
    system_call_event = {};
  }

  if (new_event_list.empty()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(d->event_list_mutex);
    d->event_list.reserve(d->event_list.size() + new_event_list.size());

    d->event_list.insert(d->event_list.end(),
                         std::make_move_iterator(new_event_list.begin()),
                         std::make_move_iterator(new_event_list.end()));
  }

  d->event_list_cv.notify_one();
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

void ManagedProbe::poll() {
  d->ebpf_probe->poll();
}

SystemCallEventList ManagedProbe::getEvents() {
  SystemCallEventList event_list;

  {
    std::unique_lock<std::mutex> lock(d->event_list_mutex);

    if (d->event_list_cv.wait_for(lock, std::chrono::seconds(1)) ==
        std::cv_status::no_timeout) {
      event_list = std::move(d->event_list);
      d->event_list.clear();
    }
  }

  return event_list;
}

std::ostream& operator<<(std::ostream& stream,
                         const SystemCallEvent& system_call_event) {
  static const auto L_syscallName =
      [](std::uint64_t syscall_number) -> const char* {
    switch (syscall_number) {
    case __NR_execve:
      return "execve";
    case __NR_open:
      return "open";
    default:
      return "UNKNOWN";
    }
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
      auto value = boost::get<std::uint64_t>(field.second);
      stream << value;
      break;
    }

    case 1U: {
      auto value = boost::get<std::int64_t>(field.second);
      stream << value;
      break;
    }

    case 2U: {
      auto value = boost::get<std::string>(field.second);
      stream << "\"" << value << "\"";
      break;
    }

    case 3U: {
      auto value = boost::get<SystemCallEvent::StringList>(field.second);
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
