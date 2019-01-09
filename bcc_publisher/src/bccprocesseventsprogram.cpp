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
#include "dockertracker.h"

#include <iomanip>

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
const TracepointDescriptorList kExecEventsTracepointList = {
  {"syscalls:sys_enter_execve"},
  {"syscalls:sys_exit_execve"},

  {"syscalls:sys_enter_execveat"},
  {"syscalls:sys_exit_execveat"}
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

  {"syscalls:sys_enter_exit"},
  {"syscalls:sys_enter_exit_group"}
};
// clang-format on

// clang-format off
const TracepointDescriptorList kFdEventsTracepointList = {
  {"syscalls:sys_enter_creat"}
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

osquery::Status getSyscallEventMap(SyscallEventMap*& event_map,
                                   const SyscallEvent& syscall_event,
                                   BCCProcessEventsContext& context) {
  event_map = nullptr;

  switch (syscall_event.header.type) {
  case SyscallEvent::Header::Type::SysEnterClone: {
    const auto& clone_data =
        boost::get<SyscallEvent::CloneData>(syscall_event.data);

    if ((clone_data.clone_flags & CLONE_THREAD) != 0) {
      event_map = &context.clone_thread_event_map;
    } else {
      event_map = &context.clone_event_map;
    }

    return osquery::Status(0);
  }

  case SyscallEvent::Header::Type::SysExitClone: {
    const auto& key = syscall_event.header.pid;

    if (context.clone_thread_event_map.count(key) > 0) {
      event_map = &context.clone_thread_event_map;
    } else {
      event_map = &context.clone_event_map;
    }

    return osquery::Status(0);
  }

  case SyscallEvent::Header::Type::SysEnterFork:
  case SyscallEvent::Header::Type::SysExitFork:
    event_map = &context.fork_event_map;
    return osquery::Status(0);

  case SyscallEvent::Header::Type::SysEnterVfork:
  case SyscallEvent::Header::Type::SysExitVfork:
    event_map = &context.vfork_event_map;
    return osquery::Status(0);

  case SyscallEvent::Header::Type::SysEnterExecve:
  case SyscallEvent::Header::Type::SysExitExecve:
    event_map = &context.execve_event_map;
    return osquery::Status(0);

  case SyscallEvent::Header::Type::SysEnterExecveat:
  case SyscallEvent::Header::Type::SysExitExecveat:
    event_map = &context.execveat_event_map;
    return osquery::Status(0);

  case SyscallEvent::Header::Type::SysEnterExit:
  case SyscallEvent::Header::Type::SysEnterExitGroup:
  case SyscallEvent::Header::Type::SysEnterCreat:
    event_map = nullptr;
    return osquery::Status(0);

  case SyscallEvent::Header::Type::KprobePidvnr: {
    const auto& key = syscall_event.header.pid;

    if (context.clone_event_map.count(key) > 0) {
      event_map = &context.clone_event_map;
    } else if (context.fork_event_map.count(key) > 0) {
      event_map = &context.fork_event_map;
    } else if (context.vfork_event_map.count(key) > 0) {
      event_map = &context.vfork_event_map;
    } else if (context.clone_thread_event_map.count(key) > 0) {
      event_map = &context.clone_thread_event_map;
    }

    if (event_map == nullptr) {
      return osquery::Status::failure("Not found");
    }

    return osquery::Status(0);
  }

  default:
    return osquery::Status::failure("Unhandled event type");
  }
}

osquery::Status processPidVnrSyscallEvent(ProcessEvent& process_event,
                                          BCCProcessEventsContext& context,
                                          const SyscallEvent& syscall_event) {
  process_event = {};

  if (syscall_event.header.type != SyscallEvent::Header::Type::KprobePidvnr) {
    throw std::logic_error("Invalid event type");
  }

  // Get the parent fork/vfork/clone event; ignore if we don't have one
  SyscallEventMap* event_map{nullptr};
  auto status = getSyscallEventMap(event_map, syscall_event, context);
  if (!status.ok()) {
    return osquery::Status(2, "Event was ignored");
  }

  // Attach this data to the existing clone/fork/vfork event
  auto key = syscall_event.header.pid;
  auto& parent_raw_event = event_map->at(key);

  auto data = boost::get<SyscallEvent::PidVnrData>(syscall_event.data);
  parent_raw_event.namespace_data = data;

  return osquery::Status(0);
}

osquery::Status processExitOrExitGroupSyscallEvent(
    ProcessEvent& process_event,
    BCCProcessEventsContext& context,
    const SyscallEvent& syscall_event) {
  process_event = {};

  if (syscall_event.header.type != SyscallEvent::Header::Type::SysEnterExit &&
      syscall_event.header.type !=
          SyscallEvent::Header::Type::SysEnterExitGroup) {
    throw std::logic_error("Invalid event type");
  }

  process_event.type = ProcessEvent::Type::Exit;
  process_event.timestamp = syscall_event.header.timestamp;
  process_event.pid = syscall_event.header.pid;
  process_event.tgid = syscall_event.header.tgid;
  process_event.uid = syscall_event.header.uid;
  process_event.gid = syscall_event.header.gid;

  auto syscall_data = boost::get<SyscallEvent::ExitData>(syscall_event.data);

  ProcessEvent::ExitData exit_data;
  exit_data.error_code = syscall_data.error_code;

  process_event.data = exit_data;

  return osquery::Status(0);
}

osquery::Status deferSyscallEventProcessing(ProcessEvent& process_event,
                                            BCCProcessEventsContext& context,
                                            const SyscallEvent& syscall_event) {
  process_event = {};

  switch (syscall_event.header.type) {
  case SyscallEvent::Header::Type::SysEnterClone:
  case SyscallEvent::Header::Type::SysEnterFork:
  case SyscallEvent::Header::Type::SysEnterVfork:
  case SyscallEvent::Header::Type::SysEnterExecve:
  case SyscallEvent::Header::Type::SysEnterExecveat:
    break;

  default:
    throw std::logic_error("Invalid event type");
  }

  SyscallEventMap* event_map{nullptr};
  auto status = getSyscallEventMap(event_map, syscall_event, context);
  if (!status.ok()) {
    return status;
  }

  const auto& key = syscall_event.header.pid;
  event_map->insert({key, syscall_event});

  return osquery::Status(2, "State has been updated");
}

osquery::Status processExecveOrExecveatSyscallExitEvent(
    ProcessEvent& process_event,
    BCCProcessEventsContext& context,
    const SyscallEvent& syscall_event) {
  process_event = {};

  if (syscall_event.header.type != SyscallEvent::Header::Type::SysExitExecve &&
      syscall_event.header.type !=
          SyscallEvent::Header::Type::SysExitExecveat) {
    throw std::logic_error("Invalid event type");
  }

  SyscallEventMap* event_map{nullptr};
  auto status = getSyscallEventMap(event_map, syscall_event, context);
  if (!status.ok()) {
    return status;
  }

  auto key = syscall_event.header.pid;

  auto it = event_map->find(key);
  if (it == event_map->end()) {
    const char* syscall_name = nullptr;
    if (syscall_event.header.type ==
        SyscallEvent::Header::Type::SysExitExecve) {
      syscall_name = "execve";
    } else {
      syscall_name = "execveat";
    }

    std::stringstream error_message;
    error_message << "Failed to locate the entry event for the " << syscall_name
                  << " event. The syscall returned "
                  << syscall_event.header.exit_code.get();

    return osquery::Status::failure(error_message.str());
  }

  auto entry_event = it->second;
  event_map->erase(it);

  process_event.type = ProcessEvent::Type::Exec;
  process_event.timestamp = syscall_event.header.timestamp;
  process_event.pid = syscall_event.header.pid;
  process_event.tgid = syscall_event.header.tgid;
  process_event.uid = syscall_event.header.uid;
  process_event.gid = syscall_event.header.gid;

  ProcessEvent::ExecData exec_data;

  const auto& entry_event_data =
      boost::get<SyscallEvent::ExecData>(entry_event.data);

  exec_data.filename = entry_event_data.filename;
  exec_data.arguments = entry_event_data.argv;
  exec_data.exit_code = syscall_event.header.exit_code.get();

  process_event.data = exec_data;

  return osquery::Status(0);
}

osquery::Status processForkOrCloneSyscallExitEvent(
    ProcessEvent& process_event,
    BCCProcessEventsContext& context,
    const SyscallEvent& syscall_event) {
  process_event = {};

  if (syscall_event.header.type != SyscallEvent::Header::Type::SysExitFork &&
      syscall_event.header.type != SyscallEvent::Header::Type::SysExitVfork &&
      syscall_event.header.type != SyscallEvent::Header::Type::SysExitClone) {
    throw std::logic_error("Invalid event type");
  }

  // Ignore the exit event happening inside the child process; we wouldn't be
  // able to match it against any enter event
  if (syscall_event.header.exit_code.get() == 0) {
    return osquery::Status(2);
  }

  SyscallEventMap* event_map{nullptr};
  auto status = getSyscallEventMap(event_map, syscall_event, context);
  if (!status.ok()) {
    return status;
  }

  auto key = syscall_event.header.pid;

  auto it = event_map->find(key);
  if (it == event_map->end()) {
    const char* syscall_name = nullptr;
    if (syscall_event.header.type == SyscallEvent::Header::Type::SysExitFork) {
      syscall_name = "fork";
    } else if (syscall_event.header.type ==
               SyscallEvent::Header::Type::SysExitVfork) {
      syscall_name = "vfork";
    } else {
      syscall_name = "clone";
    }

    std::stringstream error_message;
    error_message << "Failed to locate the entry event for the " << syscall_name
                  << " event. The syscall returned "
                  << syscall_event.header.exit_code.get();

    return osquery::Status::failure(error_message.str());
  }

  auto entry_event = event_map->at(key);
  event_map->erase(key);

  // Ignore threads
  if (entry_event.header.type == SyscallEvent::Header::Type::SysEnterClone) {
    const auto& entry_event_clone_data =
        boost::get<SyscallEvent::CloneData>(entry_event.data);

    if ((entry_event_clone_data.clone_flags & CLONE_THREAD) != 0) {
      return osquery::Status(2, "Event was ignored");
    }
  }

  process_event.type = ProcessEvent::Type::Fork;
  process_event.timestamp = syscall_event.header.timestamp;
  process_event.pid = syscall_event.header.pid;
  process_event.tgid = syscall_event.header.tgid;
  process_event.uid = syscall_event.header.uid;
  process_event.gid = syscall_event.header.gid;

  ProcessEvent::ForkData fork_data;
  fork_data.child_pid = entry_event.namespace_data.get().host_pid;
  fork_data.child_pid_namespaced =
      entry_event.namespace_data.get().namespaced_pid_list;

  process_event.data = fork_data;
  return osquery::Status(0);
}

using SyscallEventCallback = osquery::Status (*)(ProcessEvent&,
                                                 BCCProcessEventsContext& t,
                                                 const SyscallEvent&);

// clang-format off
const std::unordered_map<SyscallEvent::Header::Type, SyscallEventCallback> kSyscallEventHandlerMap = {
  {SyscallEvent::Header::Type::KprobePidvnr, processPidVnrSyscallEvent},

  {SyscallEvent::Header::Type::SysEnterExit, processExitOrExitGroupSyscallEvent},
  {SyscallEvent::Header::Type::SysEnterExitGroup, processExitOrExitGroupSyscallEvent},

  {SyscallEvent::Header::Type::SysEnterClone, deferSyscallEventProcessing},
  {SyscallEvent::Header::Type::SysEnterFork, deferSyscallEventProcessing},
  {SyscallEvent::Header::Type::SysEnterVfork, deferSyscallEventProcessing},
  {SyscallEvent::Header::Type::SysEnterExecve, deferSyscallEventProcessing},
  {SyscallEvent::Header::Type::SysEnterExecveat, deferSyscallEventProcessing},

  {SyscallEvent::Header::Type::SysExitExecve, processExecveOrExecveatSyscallExitEvent},
  {SyscallEvent::Header::Type::SysExitExecveat, processExecveOrExecveatSyscallExitEvent},

  {SyscallEvent::Header::Type::SysExitFork, processForkOrCloneSyscallExitEvent},
  {SyscallEvent::Header::Type::SysExitVfork, processForkOrCloneSyscallExitEvent},
  {SyscallEvent::Header::Type::SysExitClone, processForkOrCloneSyscallExitEvent}
};
// clang-format on
} // namespace

struct BCCProcessEventsProgram::PrivateData final {
  ebpf::BPF fork_events_bpf;
  ebpf::BPFPerfBuffer* fork_events_perf_buffer{nullptr};
  KprobeDescriptorList fork_events_kprobes;
  TracepointDescriptorList fork_events_tracepoints;

  ebpf::BPF exec_events_bpf;
  ebpf::BPFPerfBuffer* exec_events_perf_buffer{nullptr};
  TracepointDescriptorList exec_events_tracepoints;

  ebpf::BPF fd_events_bpf;
  ebpf::BPFPerfBuffer* fd_events_perf_buffer{nullptr};
  TracepointDescriptorList fd_events_tracepoints;

  BCCProcessEventsContext syscall_event_context;
  DockerTracker docker_tracker;
  std::map<std::uint64_t, SyscallEvent> syscall_event_list;
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
                 << " fork/vfork/clone/exit/exit_group events";
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
                 << " execve/execveat events";
    };

    status = d->exec_events_bpf.open_perf_buffer(
        "events", execPerfEventHandler, L_lostExecEventNotifier, this);

    if (status.code() != 0) {
      throw osquery::Status::failure("Failed to open the perf event buffer: " +
                                     status.msg());
    }

    d->exec_events_perf_buffer = d->exec_events_bpf.get_perf_buffer("events");

    // Initialize the fd_events program
    status = d->fd_events_bpf.init(bcc_probe_fd_events);
    if (status.code() != 0) {
      throw osquery::Status(1, "BCC initialization error: " + status.msg());
    }

    for (const auto& tracepoint : kFdEventsTracepointList) {
      status = d->fd_events_bpf.attach_tracepoint(
          tracepoint.name, getTracepointEventHandlerName(tracepoint));

      if (status.code() != 0) {
        throw osquery::Status::failure(
            "Failed to attach the following tracepont: " + tracepoint.name +
            ". Error: " + status.msg());
      }

      d->fd_events_tracepoints.push_back(tracepoint);
    }

    static auto L_lostFdEventNotifier = [](void*, std::uint64_t count) -> void {
      LOG(ERROR) << "BCCProcessEventsPublisher: Lost " << count << " fd events";
    };

    status = d->fd_events_bpf.open_perf_buffer(
        "events", fdPerfEventHandler, L_lostFdEventNotifier, this);

    if (status.code() != 0) {
      throw osquery::Status::failure("Failed to open the perf event buffer: " +
                                     status.msg());
    }

    d->fd_events_perf_buffer = d->fd_events_bpf.get_perf_buffer("events");

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
  const int kPollTime = 100;

  const std::vector<ebpf::BPFPerfBuffer*> kPerfBufferList = {
      d->fork_events_perf_buffer,
      d->exec_events_perf_buffer,
      d->fd_events_perf_buffer};

  for (auto perf_buffer : kPerfBufferList) {
    perf_buffer->poll(kPollTime);
  }
}

ProcessEventList BCCProcessEventsProgram::getEvents() {
  ProcessEventList process_event_list;

  auto syscall_event_list = std::move(d->syscall_event_list);
  d->syscall_event_list.clear();

  for (const auto& p : syscall_event_list) {
    const auto& syscall_event = p.second;

    ProcessEvent process_event = {};
    auto status = processSyscallEvent(
        process_event, d->syscall_event_context, syscall_event);

    if (status.getCode() != 1 &&
        syscall_event.header.type != SyscallEvent::Header::Type::KprobePidvnr) {
      d->docker_tracker.processEvent(process_event);
    }

    if (status.getCode() == 2) {
      continue;

    } else if (status.getCode() != 0) {
      LOG(ERROR) << "Failed to process the event: " << status.getMessage();
      continue;
    }

    auto timestamp = process_event.timestamp;
    process_event_list.insert({timestamp, std::move(process_event)});
  }

  return process_event_list;
}

osquery::Status BCCProcessEventsProgram::readSyscallEventHeader(
    SyscallEvent::Header& event_header,
    int& current_index,
    std::size_t& cpu_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::uint32_t event_identifier) {
  event_header = {};

  current_index =
      static_cast<int>(event_identifier & 0x00FFFFFF) % EVENT_MAP_SIZE;

  cpu_index = static_cast<std::size_t>((event_identifier >> 28) & 0x000000FF);

  try {
    readSyscallEventData(
        event_header.type, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        event_header.timestamp, current_index, event_data_table, cpu_index);

    std::uint64_t pid_tgid_value{0U};
    readSyscallEventData(
        pid_tgid_value, current_index, event_data_table, cpu_index);

    event_header.pid = static_cast<pid_t>(pid_tgid_value & 0xFFFFFFFF);
    event_header.tgid = static_cast<pid_t>(pid_tgid_value >> 32U);

    std::uint64_t uid_gid_value{0U};
    readSyscallEventData(
        uid_gid_value, current_index, event_data_table, cpu_index);

    event_header.uid = static_cast<pid_t>(uid_gid_value & 0xFFFFFFFF);
    event_header.gid = static_cast<pid_t>(uid_gid_value >> 32U);

    if (event_header.type == SyscallEvent::Header::Type::SysExitExecve ||
        event_header.type == SyscallEvent::Header::Type::SysExitExecveat ||
        event_header.type == SyscallEvent::Header::Type::SysExitFork ||
        event_header.type == SyscallEvent::Header::Type::SysExitVfork ||
        event_header.type == SyscallEvent::Header::Type::SysExitClone) {
      int exit_code = 0;
      readSyscallEventData(
          exit_code, current_index, event_data_table, cpu_index);

      event_header.exit_code = exit_code;
    }

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventString(
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
      readSyscallEventData(
          string_chunk, current_index, event_data_table, cpu_index);

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

osquery::Status BCCProcessEventsProgram::readSyscallEventExecData(
    SyscallEvent::ExecData& exec_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  exec_data = {};

  // Read the filename; this should always be present
  auto status = readSyscallEventString(
      exec_data.filename, current_index, event_data_table, cpu_index);

  if (!status.ok()) {
    return status;
  }

  // Read each argument up until the terminator
  for (std::size_t i = 0U; i < ARG_SIZE / 8U; ++i) {
    std::vector<std::uint64_t> table_data = {};
    auto s = event_data_table.get_value(current_index, table_data);
    if (s.code() != 0) {
      return osquery::Status::failure(s.msg());
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
    status = readSyscallEventString(
        buffer, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      return status;
    }

    exec_data.argv.push_back(buffer);
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventCloneData(
    SyscallEvent::CloneData& clone_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  clone_data = {};

  try {
    readSyscallEventData(
        clone_data.clone_flags, current_index, event_data_table, cpu_index);

    std::uint64_t parent_child_tid{0U};
    readSyscallEventData(
        parent_child_tid, current_index, event_data_table, cpu_index);

    clone_data.parent_tid =
        static_cast<std::uint32_t>(parent_child_tid >> 32U) & 0xFFFFFFFFU;

    clone_data.child_tid =
        static_cast<std::uint32_t>(parent_child_tid) & 0xFFFFFFFFU;

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventExitData(
    SyscallEvent::ExitData& exit_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  exit_data = {};

  try {
    readSyscallEventData(
        exit_data.error_code, current_index, event_data_table, cpu_index);

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventPidVnrData(
    SyscallEvent::PidVnrData& pidvnr_data,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  pidvnr_data = {};

  try {
    readSyscallEventData(pidvnr_data.namespace_count,
                         current_index,
                         event_data_table,
                         cpu_index);

    readSyscallEventData(
        pidvnr_data.host_pid, current_index, event_data_table, cpu_index);

    pid_t namespaced_pid;

    if (pidvnr_data.namespace_count >= 1) {
      readSyscallEventData(
          namespaced_pid, current_index, event_data_table, cpu_index);

      pidvnr_data.namespaced_pid_list.push_back(namespaced_pid);
    }

    if (pidvnr_data.namespace_count >= 2) {
      readSyscallEventData(
          namespaced_pid, current_index, event_data_table, cpu_index);

      pidvnr_data.namespaced_pid_list.push_back(namespaced_pid);
    }

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEvent(
    SyscallEvent& event,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::uint32_t event_identifier) {
  event = {};

  int current_index = 0;
  std::size_t cpu_index = 0U;

  auto status = readSyscallEventHeader(event.header,
                                       current_index,
                                       cpu_index,
                                       event_data_table,
                                       event_identifier);
  if (!status.ok()) {
    return status;
  }

  switch (event.header.type) {
  // We need to capture this both to isolate the pid_vnr call and also
  // to ignore threads
  case SyscallEvent::Header::Type::SysEnterClone: {
    SyscallEvent::CloneData clone_data = {};
    status = readSyscallEventCloneData(
        clone_data, current_index, event_data_table, cpu_index);

    event.data = clone_data;
    break;
  }

  // No processing required for these events; we grab them only to
  // know when we need to care about pid_vnr data
  case SyscallEvent::Header::Type::SysExitClone:

  case SyscallEvent::Header::Type::SysEnterFork:
  case SyscallEvent::Header::Type::SysExitFork:

  case SyscallEvent::Header::Type::SysEnterVfork:
  case SyscallEvent::Header::Type::SysExitVfork:
    status = osquery::Status(0);
    break;

  // We need the error code passed to the exit/exit_group syscall
  case SyscallEvent::Header::Type::SysEnterExit:
  case SyscallEvent::Header::Type::SysEnterExitGroup: {
    SyscallEvent::ExitData exit_data = {};
    status = readSyscallEventExitData(
        exit_data, current_index, event_data_table, cpu_index);

    event.data = exit_data;
    break;
  }

  // We expect to find the filename and arguments for the launched program
  case SyscallEvent::Header::Type::SysEnterExecve:
  case SyscallEvent::Header::Type::SysEnterExecveat: {
    SyscallEvent::ExecData exec_data = {};
    status = readSyscallEventExecData(
        exec_data, current_index, event_data_table, cpu_index);

    event.data = exec_data;
    break;
  }

  // There is no additional data for these events; they are captured
  // so that we can take the syscall exit code
  case SyscallEvent::Header::Type::SysExitExecve:
  case SyscallEvent::Header::Type::SysExitExecveat:
    status = osquery::Status(0);
    break;

  // We use this event to fill the clone/fork/vfork data with useful
  // namespace information
  case SyscallEvent::Header::Type::KprobePidvnr: {
    SyscallEvent::PidVnrData pidvnr_data = {};
    status = readSyscallEventPidVnrData(
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

osquery::Status BCCProcessEventsProgram::processSyscallEvent(
    ProcessEvent& process_event,
    BCCProcessEventsContext& context,
    const SyscallEvent& syscall_event) {
  process_event = {};

  auto it = kSyscallEventHandlerMap.find(syscall_event.header.type);
  if (it == kSyscallEventHandlerMap.end()) {
    return osquery::Status::failure("Invalid syscall event received");
  }

  auto syscall_handler = it->second;
  return syscall_handler(process_event, context, syscall_event);
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

void BCCProcessEventsProgram::fdPerfEventHandler(void* this_ptr,
                                                 void* data,
                                                 int data_size) {
  if ((data_size % 4U) != 0U) {
    LOG(ERROR) << "Invalid data size: " << data_size;
    return;
  }

  auto event_identifiers = static_cast<const std::uint32_t*>(data);
  auto& program = *static_cast<BCCProcessEventsProgram*>(this_ptr);

  auto event_data_table =
      program.d->fd_events_bpf.get_percpu_array_table<std::uint64_t>(
          "fd_event_data");

  program.processPerfEvent(event_data_table,
                           event_identifiers,
                           static_cast<std::size_t>(data_size / 4));
}

void BCCProcessEventsProgram::processPerfEvent(
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    const std::uint32_t* event_identifiers,
    std::size_t event_identifier_count) {
  for (std::size_t i = 0U; i < event_identifier_count; ++i) {
    SyscallEvent event = {};
    auto status =
        readSyscallEvent(event, event_data_table, event_identifiers[i]);

    if (!status.ok()) {
      LOG(ERROR) << "Failed to read the event header: " << status.getMessage();
      continue;
    }

    auto timestamp = event.header.timestamp;
    d->syscall_event_list.insert({timestamp, std::move(event)});
  }
}
} // namespace trailofbits
