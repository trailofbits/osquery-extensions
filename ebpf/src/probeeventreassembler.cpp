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
  case __NR_fork:
  case __NR_vfork:
  case __NR_clone:
  case __NR_exit:
  case __NR_exit_group:
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

osquery::Status ProbeEventReassembler::processProbeEventList(
    ProbeEventList& processed_probe_event_list,
    const ProbeEventList& probe_event_list) {
  processed_probe_event_list = {};

  bool error = false;
  for (const auto& probe_event : probe_event_list) {
    auto status =
        processProbeEvent(processed_probe_event_list, d->context, probe_event);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      error = true;
    }
  }

  if (error) {
    return osquery::Status::failure(
        "One or more probe events could not be successfully handled");
  }

  return osquery::Status(0);
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

  // Get or create the event tracker map for the current event
  auto event_tracker_map_it =
      process_context.event_tracker_map.find(probe_event.function_identifier);
  if (event_tracker_map_it == process_context.event_tracker_map.end()) {
    auto p = process_context.event_tracker_map.insert(
        {probe_event.function_identifier, {}});
    event_tracker_map_it = p.first;
  }

  auto& event_tracker_map = event_tracker_map_it->second;

  // Generate the new events or update the internal state
  ThreadID thread_id = probe_event.pid;
  bool exit_event = (probe_event.exit_code ? true : false);

  if (exit_event) {
    if (isEntryOnlyFunction(probe_event.function_identifier)) {
      return osquery::Status::failure("Invalid event type received");
    }

    // Get the enter event
    auto enter_event_it = event_tracker_map.find(thread_id);
    if (enter_event_it == event_tracker_map.end()) {
      return osquery::Status::failure("Failed to locate the enter event");
    }

    auto enter_event = enter_event_it->second;
    event_tracker_map.erase(enter_event_it);

    // Complete the enter event with the exit data
    enter_event.exit_code = probe_event.exit_code;

    for (const auto& p : probe_event.field_list) {
      const auto& field_name = p.first;
      const auto& field_value = p.second;

      enter_event.field_list.insert({field_name, field_value});
    }

    processed_probe_event_list.push_back(probe_event);

  } else {
    // Events that have no exit data can be emitted as they are; they other ones
    // are saved for later
    if (isEntryOnlyFunction(probe_event.function_identifier)) {
      processed_probe_event_list.push_back(probe_event);
    } else {
      event_tracker_map.insert({thread_id, probe_event});
    }
  }

  // Process forks (fork, vfork, clone) will duplicate the process state.
  // Process exits will just drop the contexts we no longer need.
  if (exit_event && (probe_event.function_identifier == __NR_fork ||
                     probe_event.function_identifier == __NR_vfork ||
                     probe_event.function_identifier == __NR_clone)) {
    auto host_pid_it = probe_event.field_list.find("host_pid");
    if (host_pid_it == probe_event.field_list.end()) {
      return osquery::Status::failure(
          "Missing host_pid field in fork/vfork/clone event");
    }

    ThreadID new_process_id = probe_event.exit_code.get();
    context.process_context_map.insert({new_process_id, process_context});

  } else if (!exit_event &&
             (probe_event.function_identifier == __NR_exit ||
              probe_event.function_identifier == __NR_exit_group)) {
    context.process_context_map.erase(process_context_it);
  }

  return osquery::Status(0);
}
} // namespace trailofbits