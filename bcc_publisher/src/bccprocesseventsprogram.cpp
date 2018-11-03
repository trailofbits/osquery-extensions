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

#include "bccprocesseventsprogram.h"

#include <iomanip>
#include <iostream>

namespace trailofbits {
namespace {
struct KprobeDescriptor final {
  bpf_probe_attach_type type;
  std::string name;
  bool translate;
};

using KprobeDescriptorList = std::vector<KprobeDescriptor>;

struct TracepointDescriptor final {
  std::string name;
};

using TracepointDescriptorList = std::vector<TracepointDescriptor>;

// clang-format off
const KprobeDescriptorList kForkEventsKprobeList = {
  {BPF_PROBE_ENTRY, "pid_vnr", false}
};
// clang-format on

// clang-format off
const TracepointDescriptorList kForkEventsTracepointList = {
  {"syscalls:sys_enter_clone"},
  {"syscalls:sys_exit_clone"},

  {"syscalls:sys_enter_fork"},
  {"syscalls:sys_exit_fork"},

  {"syscalls:sys_enter_vfork"},
  {"syscalls:sys_exit_vfork"},
};
// clang-format on

// clang-format off
const TracepointDescriptorList kExecEventsTracepointList = {
  {"syscalls:sys_enter_execve"},
  {"syscalls:sys_enter_execveat"}
};
// clang-format on

std::string getKprobeEventHandlerName(
    const KprobeDescriptor& kprobe_descriptor) {
  std::stringstream buffer;
  buffer << "on_kprobe_" << kprobe_descriptor.name << "_";

  switch (kprobe_descriptor.type) {
  case BPF_PROBE_ENTRY:
    buffer << "enter";
    break;

  case BPF_PROBE_RETURN:
    buffer << "exit";
    break;

  default:
    throw std::logic_error("Invalid probe event type");
  }

  return buffer.str();
}

std::string getTracepointEventHandlerName(
    const TracepointDescriptor& tracepoint_descriptor) {
  const char* name = tracepoint_descriptor.name.c_str();

  auto i = tracepoint_descriptor.name.find(':');
  if (i != std::string::npos) {
    name = &tracepoint_descriptor.name[i + 1];
  }

  return "on_tracepoint_" + std::string(name);
}

std::ostream& operator<<(std::ostream& stream, EventHeader::Type event_type) {
  const char* event_name{nullptr};

  switch (event_type) {
  case EventHeader::Type::SysEnterClone:
    event_name = "SysEnterClone";
    break;

  case EventHeader::Type::SysExitClone:
    event_name = "SysExitClone";
    break;

  case EventHeader::Type::SysEnterFork:
    event_name = "SysEnterFork";
    break;

  case EventHeader::Type::SysExitFork:
    event_name = "SysExitFork";
    break;

  case EventHeader::Type::SysEnterVfork:
    event_name = "SysEnterVfork";
    break;

  case EventHeader::Type::SysExitVfork:
    event_name = "SysExitVfork";
    break;

  case EventHeader::Type::SysEnterExecve:
    event_name = "SysEnterExecve";
    break;

  case EventHeader::Type::SysEnterExecveat:
    event_name = "SysEnterExecveat";
    break;

  case EventHeader::Type::KprobePidvnr:
    event_name = "KprobePidvnr";
    break;

  default:
    break;
  }

  if (event_name != nullptr) {
    stream << event_name;
  } else {
    stream << "<UnknownEventType>";
  }

  return stream;
}

std::ostream& operator<<(std::ostream& stream, const Event& event) {
  stream << std::setfill(' ') << std::setw(10) << "pid:" << event.header.pid
         << " "
         << "tgid: " << event.header.tgid << " "
         << "uid: " << event.header.uid << " "
         << "gid: " << event.header.gid << " "
         << "type: " << event.header.type << " ";

  if (event.header.type == EventHeader::Type::SysEnterExecve) {
    const auto& exec_data = boost::get<Event::ExecData>(event.data);

    stream << exec_data.filename << " ";

    for (const auto& arg : exec_data.argv) {
      stream << "\"" << arg << "\" ";
    }

    if (exec_data.argv_truncated) {
      stream << "...";
    }

  } else if (event.header.type == EventHeader::Type::KprobePidvnr) {
    const auto& pidvnr_data = boost::get<Event::PidVnrData>(event.data);

    stream << "namespace_count:" << pidvnr_data.namespace_count << " "
           << "host_pid:" << pidvnr_data.host_pid;

    if (!pidvnr_data.namespaced_pid_list.empty()) {
      stream << " namespaced_pid_list: ";

      std::stringstream buffer;
      for (auto pid : pidvnr_data.namespaced_pid_list) {
        buffer << pid << " ";
      }

      stream << buffer.str();
    }
  }

  stream << "\n";
  return stream;
}
} // namespace

struct BCCProcessEventsProgram::PrivateData final {
  ebpf::BPF fork_events_bpf;
  ebpf::BPFPerfBuffer* fork_events_perf_buffer{nullptr};
  KprobeDescriptorList fork_events_kprobes;
  TracepointDescriptorList fork_events_tracepoints;

  ebpf::BPF exec_events_bpf;
  ebpf::BPFPerfBuffer* exec_events_perf_buffer{nullptr};
  TracepointDescriptorList exec_events_tracepoints;
};

BCCProcessEventsProgram::BCCProcessEventsProgram() : d(new PrivateData) {
  try {
    // Initialize the fork_events program
    auto status = d->fork_events_bpf.init(bcc_probe_fork_events);
    if (status.code() != 0) {
      throw osquery::Status(1, "BCC initialization error: " + status.msg());
    }

    for (const auto& kprobe : kForkEventsKprobeList) {
      std::string name;
      if (kprobe.translate) {
        name = d->fork_events_bpf.get_syscall_fnname(kprobe.name);
      } else {
        name = kprobe.name;
      }

      status = d->fork_events_bpf.attach_kprobe(
          name, getKprobeEventHandlerName(kprobe), 0, kprobe.type);

      if (status.code() != 0) {
        throw osquery::Status::failure(
            "Failed to attach the following kprobe: " + name +
            ". Error: " + status.msg());
      }

      d->fork_events_kprobes.push_back(kprobe);
    }

    for (const auto& tracepoint : kForkEventsTracepointList) {
      status = d->fork_events_bpf.attach_tracepoint(
          tracepoint.name, getTracepointEventHandlerName(tracepoint));

      if (status.code() != 0) {
        throw osquery::Status::failure(
            "Failed to attach the following tracepont: " + tracepoint.name +
            ". Error: " + status.msg());
      }

      d->fork_events_tracepoints.push_back(tracepoint);
    }

    static auto L_lostForkEventNotifier = [](void*,
                                             std::uint64_t count) -> void {
      LOG(ERROR) << "BCCProcessEventsPublisher: Lost " << count
                 << " fork events";
    };

    status = d->fork_events_bpf.open_perf_buffer(
        "events", forkPerfEventHandler, L_lostForkEventNotifier, this);

    if (status.code() != 0) {
      throw osquery::Status::failure("Failed to open the perf event buffer: " +
                                     status.msg());
    }

    d->fork_events_perf_buffer = d->fork_events_bpf.get_perf_buffer("events");

    // Initialize the exec_events program
    status = d->exec_events_bpf.init(bcc_probe_exec_events);
    if (status.code() != 0) {
      throw osquery::Status(1, "BCC initialization error: " + status.msg());
    }

    for (const auto& tracepoint : kExecEventsTracepointList) {
      status = d->exec_events_bpf.attach_tracepoint(
          tracepoint.name, getTracepointEventHandlerName(tracepoint));

      if (status.code() != 0) {
        throw osquery::Status::failure(
            "Failed to attach the following tracepont: " + tracepoint.name +
            ". Error: " + status.msg());
      }

      d->exec_events_tracepoints.push_back(tracepoint);
    }

    static auto L_lostExecEventNotifier = [](void*,
                                             std::uint64_t count) -> void {
      LOG(ERROR) << "BCCProcessEventsPublisher: Lost " << count
                 << " exec events";
    };

    status = d->exec_events_bpf.open_perf_buffer(
        "events", execPerfEventHandler, L_lostExecEventNotifier, this);

    if (status.code() != 0) {
      throw osquery::Status::failure("Failed to open the perf event buffer: " +
                                     status.msg());
    }

    d->exec_events_perf_buffer = d->exec_events_bpf.get_perf_buffer("events");

  } catch (const osquery::Status&) {
    detachKprobes();
    detachTracepoints();

    throw;
  }
}

void BCCProcessEventsProgram::detachKprobes() {
  for (const auto& probe : d->fork_events_kprobes) {
    auto status = d->fork_events_bpf.detach_kprobe(probe.name, probe.type);
    if (status.code() != 0) {
      LOG(ERROR) << "Failed to detach the following kprobe: " << status.msg();
    }
  }

  d->fork_events_kprobes.clear();
}

void BCCProcessEventsProgram::detachTracepoints() {
  for (const auto& probe : d->fork_events_tracepoints) {
    auto status = d->fork_events_bpf.detach_tracepoint(probe.name);
    if (status.code() != 0) {
      LOG(ERROR) << "Failed to detach the following tracepoint: "
                 << status.msg();
    }
  }

  d->fork_events_tracepoints.clear();

  for (const auto& probe : d->exec_events_tracepoints) {
    auto status = d->exec_events_bpf.detach_tracepoint(probe.name);
    if (status.code() != 0) {
      LOG(ERROR) << "Failed to detach the following tracepoint: "
                 << status.msg();
    }
  }

  d->exec_events_tracepoints.clear();
}

osquery::Status BCCProcessEventsProgram::create(
    BCCProcessEventsProgramRef& object) {
  try {
    auto ptr = new BCCProcessEventsProgram();
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

BCCProcessEventsProgram::~BCCProcessEventsProgram() {
  detachKprobes();
  detachTracepoints();
}

void BCCProcessEventsProgram::update() {
  d->fork_events_perf_buffer->poll(100);
  d->exec_events_perf_buffer->poll(100);
}

osquery::Status BCCProcessEventsProgram::readEventHeader(
    EventHeader& event_header,
    int& current_index,
    std::size_t& cpu_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::uint32_t event_identifier) {
  event_header = {};

  current_index =
      static_cast<int>(event_identifier & 0x00FFFFFF) % EVENT_MAP_SIZE;
  cpu_index = static_cast<std::size_t>((event_identifier >> 28) & 0x000000FF);

  try {
    readEventData(
        event_header.type, current_index, event_data_table, cpu_index);

    readEventData(
        event_header.timestamp, current_index, event_data_table, cpu_index);

    std::uint64_t pid_tgid_value{0U};
    readEventData(pid_tgid_value, current_index, event_data_table, cpu_index);
    event_header.pid = static_cast<pid_t>(pid_tgid_value >> 32U);
    event_header.tgid = static_cast<pid_t>(pid_tgid_value & 0xFFFFFFFF);

    std::uint64_t uid_gid_value{0U};
    readEventData(uid_gid_value, current_index, event_data_table, cpu_index);
    event_header.uid = static_cast<pid_t>(uid_gid_value >> 32U);
    event_header.gid = static_cast<pid_t>(uid_gid_value & 0xFFFFFFFF);

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readStringEventData(
    std::string& string_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  string_data.clear();

  union {
    std::uint64_t string_chunk;
    char string_chunk_bytes[8U];
  };

  try {
    std::size_t i = 0U;
    bool terminate = false;
    auto chunk_count = (ARG_SIZE / 8U);

    for (i = 0U; i < chunk_count && !terminate; ++i) {
      string_chunk = 0U;
      readEventData(string_chunk, current_index, event_data_table, cpu_index);

      string_data.reserve(string_data.size() + 8U);
      for (auto k = 0U; k < sizeof(string_chunk_bytes); k++) {
        if (string_chunk_bytes[k] == 0) {
          terminate = true;
          break;
        }

        string_data.push_back(string_chunk_bytes[k]);
      }
    }

    auto skipped_slots = chunk_count - i;
    INCREMENT_EVENT_DATA_INDEX_BY(current_index, skipped_slots);

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readExecEventData(
    Event::ExecData& exec_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  exec_data = {};

  // Read the filename; this should always be present
  auto status = readStringEventData(
      exec_data.filename, current_index, event_data_table, cpu_index);
  if (!status.ok()) {
    return status;
  }

  // Read each argument up until the terminator
  for (std::size_t i = 0U; i < ARG_SIZE / 8U; ++i) {
    std::vector<std::uint64_t> table_data = {};
    auto s = event_data_table.get_value(current_index, table_data);
    if (s.code() != 0) {
      throw osquery::Status::failure(s.msg());
    }

    if (cpu_index >= table_data.size()) {
      return osquery::Status::failure("Invalid CPU index");
    }

    auto value = static_cast<std::uint64_t>(table_data[cpu_index]);
    if (value == VARARGS_TRUNCATION) {
      exec_data.argv_truncated = true;
      break;

    } else if (value == VARARGS_TERMINATOR) {
      exec_data.argv_truncated = false;
      break;
    }

    std::string buffer = {};
    status =
        readStringEventData(buffer, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      return status;
    }

    exec_data.argv.push_back(buffer);
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readPidVnrEventData(
    Event::PidVnrData& pidvnr_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  pidvnr_data = {};

  try {
    readEventData(pidvnr_data.namespace_count,
                  current_index,
                  event_data_table,
                  cpu_index);
    readEventData(
        pidvnr_data.host_pid, current_index, event_data_table, cpu_index);

    pid_t namespaced_pid;

    if (pidvnr_data.namespace_count >= 1) {
      readEventData(namespaced_pid, current_index, event_data_table, cpu_index);
      pidvnr_data.namespaced_pid_list.push_back(namespaced_pid);
    }

    if (pidvnr_data.namespace_count >= 2) {
      readEventData(namespaced_pid, current_index, event_data_table, cpu_index);
      pidvnr_data.namespaced_pid_list.push_back(namespaced_pid);
    }

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readEvent(
    Event& event,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::uint32_t event_identifier) {
  event = {};

  int current_index = 0;
  std::size_t cpu_index = 0U;

  auto status = readEventHeader(event.header,
                                current_index,
                                cpu_index,
                                event_data_table,
                                event_identifier);
  if (!status.ok()) {
    return status;
  }

  switch (event.header.type) {
  // No processing required for these events; we grab them only to
  // know when we need to care about pid_vnr data
  case EventHeader::Type::SysEnterClone:
  case EventHeader::Type::SysExitClone:
  case EventHeader::Type::SysEnterFork:
  case EventHeader::Type::SysExitFork:
  case EventHeader::Type::SysEnterVfork:
  case EventHeader::Type::SysExitVfork:
    status = osquery::Status(0);
    break;

  // We expect to find the filename and arguments for the launched program
  case EventHeader::Type::SysEnterExecve:
  case EventHeader::Type::SysEnterExecveat: {
    Event::ExecData exec_data = {};
    status = readExecEventData(
        exec_data, current_index, event_data_table, cpu_index);

    event.data = exec_data;
    break;
  }

  // We use this event to fill the clone/fork/vfork data with useful
  // namespace information
  case EventHeader::Type::KprobePidvnr: {
    Event::PidVnrData pidvnr_data = {};
    status = readPidVnrEventData(
        pidvnr_data, current_index, event_data_table, cpu_index);

    event.data = pidvnr_data;
    break;
  }

  default:
    status = osquery::Status::failure("Unhandled event type");
    break;
  }

  return status;
}

void BCCProcessEventsProgram::forkPerfEventHandler(void* this_ptr,
                                                   void* data,
                                                   int data_size) {
  if ((data_size % 4U) != 0U) {
    LOG(ERROR) << "Invalid data size: " << data_size;
    return;
  }

  auto event_identifiers = static_cast<const std::uint32_t*>(data);
  auto& program = *static_cast<BCCProcessEventsProgram*>(this_ptr);

  auto event_data_table =
      program.d->fork_events_bpf.get_percpu_array_table<std::uint64_t>(
          "fork_event_data");

  program.processPerfEvent(event_data_table,
                           event_identifiers,
                           static_cast<std::size_t>(data_size / 4));
}

void BCCProcessEventsProgram::execPerfEventHandler(void* this_ptr,
                                                   void* data,
                                                   int data_size) {
  if ((data_size % 4U) != 0U) {
    LOG(ERROR) << "Invalid data size: " << data_size;
    return;
  }

  auto event_identifiers = static_cast<const std::uint32_t*>(data);
  auto& program = *static_cast<BCCProcessEventsProgram*>(this_ptr);

  auto event_data_table =
      program.d->exec_events_bpf.get_percpu_array_table<std::uint64_t>(
          "exec_event_data");

  program.processPerfEvent(event_data_table,
                           event_identifiers,
                           static_cast<std::size_t>(data_size / 4));
}

void BCCProcessEventsProgram::processPerfEvent(
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    const std::uint32_t* event_identifiers,
    std::size_t event_identifier_count) {
  for (std::size_t i = 0U; i < event_identifier_count; ++i) {
    Event event = {};
    auto status = readEvent(event, event_data_table, event_identifiers[i]);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to read the event header: " << status.getMessage();
      continue;
    }

    LOG(ERROR) << event;
  }
}
} // namespace trailofbits
