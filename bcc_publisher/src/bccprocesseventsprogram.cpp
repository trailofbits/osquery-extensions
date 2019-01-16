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

#include <chrono>
#include <thread>

#include <future>

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

struct BPFProgramDescriptor final {
  std::string friendly_name;
  std::string source_code;
  KprobeDescriptorList kprobe_list;
  TracepointDescriptorList tracepoint_list;
};

using SyscallEventCallback = osquery::Status (*)(ProcessEvent&,
                                                 BCCProcessEventsContext& t,
                                                 const SyscallEvent&);

using EventDataTable = ebpf::BPFPercpuArrayTable<std::uint64_t>;
using BPFRef = std::unique_ptr<ebpf::BPF>;

struct BPFProgramInstance final {
  BPFProgramInstance(EventDataTable event_data_table_)
      : event_data_table(std::move(event_data_table_)) {}

  std::string friendly_name;
  BPFRef bpf;
  ebpf::BPFPerfBuffer* perf_event_buffer{nullptr};
  EventDataTable event_data_table;
  BCCProcessEventsProgram* object{nullptr};
  KprobeDescriptorList kprobe_list;
  TracepointDescriptorList tracepoint_list;
};

using BPFProgramInstanceRef = std::unique_ptr<BPFProgramInstance>;

using BPFProgramInstanceRefList = std::vector<BPFProgramInstanceRef>;

using SyscallEventDataReader = osquery::Status (*)(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index);

// clang-format off
const std::vector<BPFProgramDescriptor> kBpfProgramDescriptorList = {
  {
    // Probe name
    "fork_events",

    // Probe source
    kBccProbe_fork_events,

    // kprobes
    {
      { BPF_PROBE_ENTRY, "pid_vnr", false }
    },

    // Tracepoints
    {
      { "syscalls:sys_enter_clone" },
      { "syscalls:sys_exit_clone" },

      { "syscalls:sys_enter_fork" },
      { "syscalls:sys_exit_fork" },

      { "syscalls:sys_enter_vfork" },
      { "syscalls:sys_exit_vfork" },

      { "syscalls:sys_enter_exit" },
      { "syscalls:sys_enter_exit_group" }
    }
  },

  {
    // Probe name
    "exec_events",

    // Probe source
    kBccProbe_exec_events,

    // kprobes
    {},

    // Tracepoints
    {
      { "syscalls:sys_enter_execve" },
      { "syscalls:sys_exit_execve" },

      { "syscalls:sys_enter_execveat" },
      { "syscalls:sys_exit_execveat" }
    }
  },

  {
    // Probe name
    "open_events",

    // Probe source
    kBccProbe_open_events,

    // kprobes
    {},

    // Tracepoints
    {
      { "syscalls:sys_enter_open" },
      { "syscalls:sys_exit_open" },

      { "syscalls:sys_enter_openat" },
      { "syscalls:sys_exit_openat" },

      { "syscalls:sys_enter_open_by_handle_at" },
      { "syscalls:sys_exit_open_by_handle_at" },

      { "syscalls:sys_enter_name_to_handle_at" },
      { "syscalls:sys_exit_name_to_handle_at" }
    }
  },

  {
    // Probe name
    "create_mknod_events",

    // Probe source
    kBccProbe_create_mknod_events,

    // kprobes
    {},

    // Tracepoints
    {
      { "syscalls:sys_enter_creat" },
      { "syscalls:sys_exit_creat" },

      { "syscalls:sys_enter_mknod" },
      { "syscalls:sys_exit_mknod" },

      { "syscalls:sys_enter_mknodat" },
      { "syscalls:sys_exit_mknodat" },
    }
  },

  {
    // Probe name
    "dup_close_events",

    // Probe source
    kBccProbe_dup_close_events,

    // kprobes
    {},

    // Tracepoints
    {
      { "syscalls:sys_enter_dup" },
      { "syscalls:sys_exit_dup" },

      { "syscalls:sys_enter_dup2" },
      { "syscalls:sys_exit_dup2" },

      { "syscalls:sys_enter_dup3" },
      { "syscalls:sys_exit_dup3" },

      { "syscalls:sys_enter_close" },
      { "syscalls:sys_exit_close" }
    }
  },

  {
    // Probe name
    "socket_fd_events",

    // Probe source
    kBccProbe_socket_fd_events,

    // kprobes
    {},

    // Tracepoints
    {
      { "syscalls:sys_enter_socket" },
      { "syscalls:sys_exit_socket" },

      { "syscalls:sys_enter_socketpair" },
      { "syscalls:sys_exit_socketpair" }
    }
  }
};
// clang-format on

void initializeProcessEvent(ProcessEvent& process_event,
                            ProcessEvent::Type event_type,
                            const SyscallEvent& syscall_event) {
  process_event = {};

  process_event.type = event_type;
  process_event.timestamp = syscall_event.header.timestamp;
  process_event.pid = syscall_event.header.pid;
  process_event.tgid = syscall_event.header.tgid;
  process_event.uid = syscall_event.header.uid;
  process_event.gid = syscall_event.header.gid;
}

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

  initializeProcessEvent(
      process_event, ProcessEvent::Type::Exit, syscall_event);

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

  initializeProcessEvent(
      process_event, ProcessEvent::Type::Exec, syscall_event);

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

  initializeProcessEvent(
      process_event, ProcessEvent::Type::Fork, syscall_event);

  ProcessEvent::ForkData fork_data;
  fork_data.child_pid = entry_event.namespace_data.get().host_pid;
  fork_data.child_pid_namespaced =
      entry_event.namespace_data.get().namespaced_pid_list;

  process_event.data = fork_data;
  return osquery::Status(0);
}

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

// clang-format off
const std::map<SyscallEvent::Header::Type, SyscallEventDataReader> kSyscallEventDataReaderMap = {
  { SyscallEvent::Header::Type::SysEnterExecve, BCCProcessEventsProgram::readSyscallEventExecData },
  { SyscallEvent::Header::Type::SysEnterExecveat, BCCProcessEventsProgram::readSyscallEventExecData },
  { SyscallEvent::Header::Type::SysEnterClone, BCCProcessEventsProgram::readSyscallEventCloneData },
  { SyscallEvent::Header::Type::SysEnterExit, BCCProcessEventsProgram::readSyscallEventExitData },
  { SyscallEvent::Header::Type::SysEnterExitGroup, BCCProcessEventsProgram::readSyscallEventExitData },
  { SyscallEvent::Header::Type::KprobePidvnr, BCCProcessEventsProgram::readSyscallEventPidVnrData },
  { SyscallEvent::Header::Type::SysEnterCreat, BCCProcessEventsProgram::readSyscallEventCreatData },
  { SyscallEvent::Header::Type::SysEnterMknod, BCCProcessEventsProgram::readSyscallEventMknodData },
  { SyscallEvent::Header::Type::SysEnterMknodat, BCCProcessEventsProgram::readSyscallEventMknodatData },
  { SyscallEvent::Header::Type::SysEnterOpen, BCCProcessEventsProgram::readSyscallEventOpenData },
  { SyscallEvent::Header::Type::SysEnterOpenat, BCCProcessEventsProgram::readSyscallEventOpenatData },
  { SyscallEvent::Header::Type::SysEnterOpen_by_handle_at, BCCProcessEventsProgram::readSyscallEventOpenByHandleAtData },
  { SyscallEvent::Header::Type::SysEnterName_to_handle_at, BCCProcessEventsProgram::readSyscallEventNameToHandleAtData },
  { SyscallEvent::Header::Type::SysEnterClose, BCCProcessEventsProgram::readSyscallEventCloseData },
  { SyscallEvent::Header::Type::SysEnterDup, BCCProcessEventsProgram::readSyscallEventDupData },
  { SyscallEvent::Header::Type::SysEnterDup2, BCCProcessEventsProgram::readSyscallEventDup2Data },
  { SyscallEvent::Header::Type::SysEnterDup3, BCCProcessEventsProgram::readSyscallEventDup3Data },
  { SyscallEvent::Header::Type::SysEnterSocket, BCCProcessEventsProgram::readSyscallEventSocketData },
  { SyscallEvent::Header::Type::SysEnterSocketpair, BCCProcessEventsProgram::readSyscallEventSocketPairData },

  { SyscallEvent::Header::Type::SysExitExecve, nullptr },
  { SyscallEvent::Header::Type::SysExitExecveat, nullptr },
  { SyscallEvent::Header::Type::SysEnterFork, nullptr },
  { SyscallEvent::Header::Type::SysExitFork, nullptr },
  { SyscallEvent::Header::Type::SysEnterVfork, nullptr },
  { SyscallEvent::Header::Type::SysExitVfork, nullptr },
  { SyscallEvent::Header::Type::SysExitClone, nullptr },
  { SyscallEvent::Header::Type::SysExitCreat, nullptr },
  { SyscallEvent::Header::Type::SysExitMknod, nullptr },
  { SyscallEvent::Header::Type::SysExitMknodat, nullptr },
  { SyscallEvent::Header::Type::SysExitOpen, nullptr },
  { SyscallEvent::Header::Type::SysExitOpenat, nullptr },
  { SyscallEvent::Header::Type::SysExitOpen_by_handle_at, nullptr },
  { SyscallEvent::Header::Type::SysExitName_to_handle_at, nullptr },
  { SyscallEvent::Header::Type::SysExitClose, nullptr },
  { SyscallEvent::Header::Type::SysExitDup, nullptr },
  { SyscallEvent::Header::Type::SysExitDup2, nullptr },
  { SyscallEvent::Header::Type::SysExitDup3, nullptr },
  { SyscallEvent::Header::Type::SysExitSocket, nullptr },
  { SyscallEvent::Header::Type::SysExitSocketpair, nullptr }
};
// clang-format on
} // namespace

struct BCCProcessEventsProgram::PrivateData final {
  BPFProgramInstanceRefList bpf_program_instance_list;

  BCCProcessEventsContext syscall_event_context;
  DockerTracker docker_tracker;

  std::mutex syscall_event_list_mutex;
  std::condition_variable syscall_event_list_cv;
  std::map<std::uint64_t, SyscallEvent> syscall_event_list;
};

BCCProcessEventsProgram::BCCProcessEventsProgram() : d(new PrivateData) {
  try {
    for (const auto& program_descriptor : kBpfProgramDescriptorList) {
      auto bpf = std::make_unique<ebpf::BPF>();

      auto bpf_status = bpf->init(program_descriptor.source_code);
      if (bpf_status.code() != 0) {
        throw osquery::Status::failure("BCC initialization error: " +
                                       bpf_status.msg());
      }

      for (const auto& tracepoint : program_descriptor.tracepoint_list) {
        bpf_status = bpf->attach_tracepoint(
            tracepoint.name, getTracepointEventHandlerName(tracepoint));

        if (bpf_status.code() != 0) {
          throw osquery::Status::failure(
              "Failed to attach the following tracepont: " + tracepoint.name +
              ". Error: " + bpf_status.msg());
        }
      }

      for (const auto& kprobe : program_descriptor.kprobe_list) {
        std::string name;
        if (kprobe.translate) {
          name = bpf->get_syscall_fnname(kprobe.name);
        } else {
          name = kprobe.name;
        }

        bpf_status = bpf->attach_kprobe(
            name, getKprobeEventHandlerName(kprobe), 0, kprobe.type);

        if (bpf_status.code() != 0) {
          throw osquery::Status::failure(
              "Failed to attach the following kprobe: " + name +
              ". Error: " + bpf_status.msg());
        }
      }

      auto event_data_table =
          bpf->get_percpu_array_table<std::uint64_t>("perf_event_data");

      auto program_data =
          std::make_unique<BPFProgramInstance>(std::move(event_data_table));

      program_data->friendly_name = program_descriptor.friendly_name;
      program_data->object = this;
      program_data->bpf = std::move(bpf);

      static auto L_lostEventCallback = [](void* user_defined,
                                           std::uint64_t count) -> void {
        auto program_data = reinterpret_cast<BPFProgramInstance*>(user_defined);
        LOG(ERROR) << "BCCProcessEventsProgram/" << program_data->friendly_name
                   << ": lost " << count << " events ";
      };

      static auto L_eventCallback =
          [](void* user_defined, void* data, int data_size) -> void {
        auto program_data = reinterpret_cast<BPFProgramInstance*>(user_defined);

        if ((data_size % 4U) != 0U) {
          LOG(ERROR) << "Invalid data size: " << data_size;
          return;
        }

        auto event_identifiers = static_cast<const std::uint32_t*>(data);
        auto& event_data_table = program_data->event_data_table;

        program_data->object->processPerfEvent(
            event_data_table,
            event_identifiers,
            static_cast<std::size_t>(data_size / 4));
      };

      bpf_status = program_data->bpf->open_perf_buffer(
          "events", L_eventCallback, L_lostEventCallback, program_data.get());

      if (bpf_status.code() != 0) {
        throw osquery::Status::failure(
            "Failed to open the perf event buffer: " + bpf_status.msg());
      }

      program_data->perf_event_buffer =
          program_data->bpf->get_perf_buffer("events");

      d->bpf_program_instance_list.push_back(std::move(program_data));
      program_data.release();
    }

  } catch (const osquery::Status&) {
    detachProbes();
    throw;
  }
}

void BCCProcessEventsProgram::detachProbes() {
  for (auto& program_data : d->bpf_program_instance_list) {
    for (auto& probe : program_data->kprobe_list) {
      auto bpf_status =
          program_data->bpf->detach_kprobe(probe.name, probe.type);
      if (bpf_status.code() != 0) {
        LOG(ERROR) << "Failed to detach the following kprobe: " << probe.name
                   << ". " << bpf_status.msg();
      }
    }

    for (auto& tracepoint : program_data->tracepoint_list) {
      auto bpf_status = program_data->bpf->detach_tracepoint(tracepoint.name);
      if (bpf_status.code() != 0) {
        LOG(ERROR) << "Failed to detach the following tracepoint: "
                   << tracepoint.name << ". " << bpf_status.msg();
      }
    }
  }
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
  detachProbes();
}

osquery::Status BCCProcessEventsProgram::initialize() {
  static auto L_pollThread =
      [](ebpf::BPFPerfBuffer* perf_event_buffer) -> void {
    const int kPollTime = 100;

    while (true) {
      perf_event_buffer->poll(kPollTime);
    }
  };

  try {
    for (auto& program_instance : d->bpf_program_instance_list) {
      auto poll_thread =
          new std::thread(L_pollThread, program_instance->perf_event_buffer);
      poll_thread->detach();
    }

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");
  }
}

ProcessEventList BCCProcessEventsProgram::getEvents() {
  std::map<std::uint64_t, SyscallEvent> syscall_event_list;

  {
    std::unique_lock<std::mutex> lock(d->syscall_event_list_mutex);

    if (d->syscall_event_list_cv.wait_for(lock, std::chrono::seconds(1)) !=
        std::cv_status::no_timeout) {
      return {};
    }

    syscall_event_list = std::move(d->syscall_event_list);
    d->syscall_event_list.clear();
  }

  ProcessEventList process_event_list;

  for (const auto& p : syscall_event_list) {
    const auto& syscall_event = p.second;

    ProcessEvent process_event = {};
    auto status = processSyscallEvent(
        process_event, d->syscall_event_context, syscall_event);

    if (status.getCode() != 1 &&
        syscall_event.header.type != SyscallEvent::Header::Type::KprobePidvnr) {
      d->docker_tracker.processEvent(process_event);
    }

    continue;

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

    switch (event_header.type) {
    case SyscallEvent::Header::Type::SysExitExecve:
    case SyscallEvent::Header::Type::SysExitExecveat:
    case SyscallEvent::Header::Type::SysExitFork:
    case SyscallEvent::Header::Type::SysExitVfork:
    case SyscallEvent::Header::Type::SysExitClone:
    case SyscallEvent::Header::Type::SysExitCreat:
    case SyscallEvent::Header::Type::SysExitMknod:
    case SyscallEvent::Header::Type::SysExitMknodat:
    case SyscallEvent::Header::Type::SysExitOpen:
    case SyscallEvent::Header::Type::SysExitOpenat:
    case SyscallEvent::Header::Type::SysExitOpen_by_handle_at:
    case SyscallEvent::Header::Type::SysExitName_to_handle_at:
    case SyscallEvent::Header::Type::SysExitClose:
    case SyscallEvent::Header::Type::SysExitDup:
    case SyscallEvent::Header::Type::SysExitDup2:
    case SyscallEvent::Header::Type::SysExitDup3:
    case SyscallEvent::Header::Type::SysExitSocket:
    case SyscallEvent::Header::Type::SysExitSocketpair: {
      int exit_code = 0;
      readSyscallEventData(
          exit_code, current_index, event_data_table, cpu_index);

      event_header.exit_code = exit_code;
      break;
    }

    case SyscallEvent::Header::Type::SysEnterExecve:
    case SyscallEvent::Header::Type::SysEnterExecveat:
    case SyscallEvent::Header::Type::SysEnterFork:
    case SyscallEvent::Header::Type::SysEnterVfork:
    case SyscallEvent::Header::Type::SysEnterClone:
    case SyscallEvent::Header::Type::SysEnterCreat:
    case SyscallEvent::Header::Type::SysEnterMknod:
    case SyscallEvent::Header::Type::SysEnterMknodat:
    case SyscallEvent::Header::Type::SysEnterOpen:
    case SyscallEvent::Header::Type::SysEnterOpenat:
    case SyscallEvent::Header::Type::SysEnterOpen_by_handle_at:
    case SyscallEvent::Header::Type::SysEnterName_to_handle_at:
    case SyscallEvent::Header::Type::SysEnterClose:
    case SyscallEvent::Header::Type::SysEnterDup:
    case SyscallEvent::Header::Type::SysEnterDup2:
    case SyscallEvent::Header::Type::SysEnterDup3:
    case SyscallEvent::Header::Type::SysEnterSocket:
    case SyscallEvent::Header::Type::SysEnterSocketpair:
    case SyscallEvent::Header::Type::SysEnterExit:
    case SyscallEvent::Header::Type::SysEnterExitGroup:
    case SyscallEvent::Header::Type::KprobePidvnr:
      break;
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
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::ExecData exec_data = {};

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

  syscall_event.data = exec_data;
  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventCloneData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::CloneData clone_data = {};

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

    syscall_event.data = clone_data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventExitData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::ExitData exit_data = {};

  try {
    readSyscallEventData(
        exit_data.error_code, current_index, event_data_table, cpu_index);

    syscall_event.data = exit_data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventPidVnrData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::PidVnrData pidvnr_data = {};

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

    syscall_event.data = pidvnr_data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventCreatData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::CreateData data = {};

  try {
    auto status = readSyscallEventString(
        data.path, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(data.mode, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventMknodData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::MknodData data = {};

  try {
    auto status = readSyscallEventString(
        data.path, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(data.mode, current_index, event_data_table, cpu_index);
    readSyscallEventData(data.dev, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventMknodatData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::MknodatData data = {};

  try {
    readSyscallEventData(data.dfd, current_index, event_data_table, cpu_index);

    auto status = readSyscallEventString(
        data.filename, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(data.mode, current_index, event_data_table, cpu_index);
    readSyscallEventData(data.dev, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventOpenData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::OpenData data = {};

  try {
    auto status = readSyscallEventString(
        data.filename, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(
        data.flags, current_index, event_data_table, cpu_index);

    readSyscallEventData(data.mode, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventOpenatData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::OpenatData data = {};

  try {
    readSyscallEventData(data.dfd, current_index, event_data_table, cpu_index);

    auto status = readSyscallEventString(
        data.filename, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(
        data.flags, current_index, event_data_table, cpu_index);

    readSyscallEventData(data.mode, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventOpenByHandleAtData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::OpenByHandleAtData data = {};

  try {
    readSyscallEventData(
        data.mountdirfd, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.flags, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventNameToHandleAtData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::NameToHandleAtData data = {};

  try {
    readSyscallEventData(data.dfd, current_index, event_data_table, cpu_index);

    auto status = readSyscallEventString(
        data.name, current_index, event_data_table, cpu_index);

    if (!status.ok()) {
      throw status;
    }

    readSyscallEventData(
        data.mntid, current_index, event_data_table, cpu_index);

    readSyscallEventData(data.flag, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status BCCProcessEventsProgram::readSyscallEventCloseData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::CloseData data = {};

  try {
    readSyscallEventData(data.fd, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventDupData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::DupData data = {};

  try {
    readSyscallEventData(
        data.fildes, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventDup2Data(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::Dup2Data data = {};

  try {
    readSyscallEventData(
        data.oldfd, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.newfd, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventDup3Data(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::Dup3Data data = {};

  try {
    readSyscallEventData(
        data.oldfd, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.newfd, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.flags, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventSocketData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::SocketData data = {};

  try {
    readSyscallEventData(
        data.family, current_index, event_data_table, cpu_index);

    readSyscallEventData(data.type, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.protocol, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEventSocketPairData(
    SyscallEvent& syscall_event,
    int& current_index,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t cpu_index) {
  SyscallEvent::SocketpairData data = {};

  try {
    readSyscallEventData(
        data.family, current_index, event_data_table, cpu_index);

    readSyscallEventData(data.type, current_index, event_data_table, cpu_index);

    readSyscallEventData(
        data.protocol, current_index, event_data_table, cpu_index);

    syscall_event.data = data;
    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status BCCProcessEventsProgram::readSyscallEvent(
    SyscallEvent& syscall_event,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::uint32_t event_identifier) {
  syscall_event = {};

  int current_index = 0;
  std::size_t cpu_index = 0U;

  auto status = readSyscallEventHeader(syscall_event.header,
                                       current_index,
                                       cpu_index,
                                       event_data_table,
                                       event_identifier);
  if (!status.ok()) {
    return status;
  }

  auto data_reader_it =
      kSyscallEventDataReaderMap.find(syscall_event.header.type);

  if (data_reader_it == kSyscallEventDataReaderMap.end()) {
    throw std::logic_error("Unhandled event type");
  }

  auto data_reader = data_reader_it->second;

  if (data_reader != nullptr) {
    status =
        data_reader(syscall_event, current_index, event_data_table, cpu_index);
  } else {
    status = osquery::Status(0);
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

void BCCProcessEventsProgram::processPerfEvent(
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    const std::uint32_t* event_identifiers,
    std::size_t event_identifier_count) {
  std::vector<SyscallEvent> new_event_list;

  for (std::size_t i = 0U; i < event_identifier_count; ++i) {
    SyscallEvent event = {};
    auto status =
        readSyscallEvent(event, event_data_table, event_identifiers[i]);

    if (!status.ok()) {
      LOG(ERROR) << "Failed to read the event header: " << status.getMessage();
      continue;
    }

    new_event_list.push_back(std::move(event));
  }

  if (new_event_list.empty()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(d->syscall_event_list_mutex);

    for (auto& event : new_event_list) {
      auto timestamp = event.header.timestamp;
      d->syscall_event_list.insert({timestamp, std::move(event)});
    }

    new_event_list.clear();
  }

  d->syscall_event_list_cv.notify_all();
}
} // namespace trailofbits
