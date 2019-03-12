/*
 * Copyright (c) 2019-present Trail of Bits, Inc.
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

#include "probeeventreassembler.h"
#include "probes/kprobe_group/header.h"

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
bool isKnownFunction(std::uint64_t function_identifier) {
  switch (function_identifier) {
  case __NR_close:
  case __NR_dup:
  case __NR_dup2:
  case __NR_dup3:
  case __NR_execve:
  case __NR_execveat:
  case __NR_socket:
  case __NR_bind:
  case __NR_connect:
  case KPROBE_FORK_CALL:
  case KPROBE_VFORK_CALL:
  case KPROBE_CLONE_CALL:
  case __NR_exit:
  case __NR_exit_group:
  case __NR_fcntl:
    return true;

  case KPROBE_PIDVNR_CALL:
    return true;

  default:
    return false;
  }
}

bool isEntryOnlyFunction(std::uint64_t function_identifier) {
  switch (function_identifier) {
  case __NR_exit:
  case __NR_exit_group:
    return true;

  case KPROBE_PIDVNR_CALL:
    return true;

  default:
    return false;
  }
}
} // namespace

struct ProbeEventReassembler::PrivateData final {
  ProbeEventReassemblerContext context;
};

ProbeEventReassembler::ProbeEventReassembler() : d(new PrivateData) {}

osquery::Status ProbeEventReassembler::create(ProbeEventReassemblerRef& obj) {
  try {
    obj.reset();

    auto ptr = new ProbeEventReassembler();
    obj.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ProbeEventReassembler::~ProbeEventReassembler() {}

osquery::Status ProbeEventReassembler::processProbeEvent(
    ProbeEventList& processed_probe_event_list, const ProbeEvent& probe_event) {
  return processProbeEvent(processed_probe_event_list, d->context, probe_event);
}

osquery::Status ProbeEventReassembler::processProbeEvent(
    ProbeEventList& processed_probe_event_list,
    ProbeEventReassemblerContext& context,
    const ProbeEvent& probe_event) {
  if (!isKnownFunction(probe_event.function_identifier)) {
    return osquery::Status(0, "Event was ignored");
  }

  // Get or create the process context
  ProcessID process_id = probe_event.tgid;

  auto process_context_it = context.process_context_map.find(process_id);
  if (process_context_it == context.process_context_map.end()) {
    ProcessContext new_process_context;
    new_process_context.process_id = process_id;

    auto p =
        context.process_context_map.insert({process_id, new_process_context});

    process_context_it = p.first;
  }

  auto& process_context = process_context_it->second;

  // Get or create the thread context
  ThreadID thread_id = probe_event.pid;

  auto thread_context_it = process_context.thread_context_map.find(thread_id);

  if (thread_context_it == process_context.thread_context_map.end()) {
    auto p = process_context.thread_context_map.insert({thread_id, {}});

    thread_context_it = p.first;
  }

  auto& thread_context = thread_context_it->second;

  // Generate new events or update the internal state
  bool exit_event = (probe_event.exit_code ? true : false);

  if (exit_event) {
    if (isEntryOnlyFunction(probe_event.function_identifier)) {
      return osquery::Status::failure("Invalid event type received");
    }

    // Ignore failed forks! Also ignore them when exiting from the child process
    // side
    if (probe_event.function_identifier == KPROBE_FORK_CALL ||
        probe_event.function_identifier == KPROBE_VFORK_CALL ||
        probe_event.function_identifier == KPROBE_CLONE_CALL) {
      auto exit_code = probe_event.exit_code.get();
      if (exit_code == 0 || exit_code == -1) {
        return osquery::Status(0);
      }
    }

    // Get the enter event
    auto enter_event_it = thread_context.find(probe_event.function_identifier);
    if (enter_event_it == thread_context.end()) {
      auto error_message =
          std::string("failed to locate the enter event for function #") +
          std::to_string(probe_event.function_identifier) + " at timestamp " +
          std::to_string(probe_event.timestamp);
      return osquery::Status::failure(error_message);
    }

    auto enter_event = enter_event_it->second;
    thread_context.erase(enter_event_it);

    // Skip thread creation events
    bool thread_creation_event = false;

    if (enter_event.function_identifier == __NR_clone) {
      std::int64_t clone_flags = {};
      auto status = getProbeEventField(clone_flags, probe_event, "clone_flags");
      if (!status.ok()) {
        return status;
      }

      thread_creation_event = ((clone_flags & CLONE_THREAD) != 0);
    }

    if (thread_creation_event) {
      return osquery::Status(0);
    }

    // Complete the enter event with the exit data
    enter_event.exit_code = probe_event.exit_code;

    for (const auto& field : probe_event.field_list) {
      enter_event.field_list.insert({field.first, field.second});
    }

    processed_probe_event_list.push_back(enter_event);

    // Process forks (fork, vfork, clone)
    if (enter_event.function_identifier == KPROBE_FORK_CALL ||
        enter_event.function_identifier == KPROBE_VFORK_CALL ||
        enter_event.function_identifier == KPROBE_CLONE_CALL) {
      std::int64_t host_pid = {};
      auto status = getProbeEventField(host_pid, probe_event, "host_pid");
      if (!status.ok()) {
        return status;
      }

      context.process_context_map.insert(
          {static_cast<ThreadID>(host_pid), process_context});
    }

  } else {
    // pid_vnr events are used to add additional data to previous
    // fork/vfork/clone system calls
    if (probe_event.function_identifier == KPROBE_PIDVNR_CALL) {
      for (auto prev_event_type :
           {KPROBE_FORK_CALL, KPROBE_VFORK_CALL, KPROBE_CLONE_CALL}) {
        auto prev_event_it = thread_context.find(prev_event_type);
        if (prev_event_it != thread_context.end()) {
          auto& prev_probe_event = prev_event_it->second;

          for (const auto& field : probe_event.field_list) {
            prev_probe_event.field_list.insert({field.first, field.second});
          }
        }
      }

    } else {
      // Events that have no exit data can be emitted as they are; the other
      // ones are saved for later
      if (isEntryOnlyFunction(probe_event.function_identifier)) {
        processed_probe_event_list.push_back(probe_event);

        // Process exits will just drop the contexts we no longer need.
        if (probe_event.function_identifier == __NR_exit ||
            probe_event.function_identifier == __NR_exit_group) {
          context.process_context_map.erase(process_context_it);
        }

      } else {
        thread_context.insert({probe_event.function_identifier, probe_event});
      }
    }
  }

  return osquery::Status(0);
}
} // namespace trailofbits