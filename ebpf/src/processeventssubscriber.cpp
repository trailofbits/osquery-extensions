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

#include "processeventssubscriber.h"
#include "probes/kprobe_group/header.h"

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
// clang-format off
const std::unordered_map<std::uint64_t, std::string> kSyscallNameTable = {
  { __NR_execve, "execve" },
  { __NR_execveat, "execveat" },
  { KPROBE_FORK_CALL, "fork" },
  { KPROBE_VFORK_CALL, "vfork" },
  { KPROBE_CLONE_CALL, "clone" },
  { __NR_exit, "exit" },
  { __NR_exit_group, "exit_group" }
};
// clang-format on

const std::string& getSystemCallName(std::uint64_t system_call_nr) {
  static const std::string kUnknownSystemCallName{"unknown"};

  auto name_it = kSyscallNameTable.find(system_call_nr);
  if (name_it == kSyscallNameTable.end()) {
    return kUnknownSystemCallName;
  }

  return name_it->second;
}
} // namespace

// clang-format off
BEGIN_TABLE(ebpf_process_events)
  TABLE_COLUMN(timestamp, osquery::TEXT_TYPE)
  TABLE_COLUMN(ppid, osquery::TEXT_TYPE)
  TABLE_COLUMN(pid, osquery::TEXT_TYPE)
  TABLE_COLUMN(tid, osquery::TEXT_TYPE)
  TABLE_COLUMN(uid, osquery::TEXT_TYPE)
  TABLE_COLUMN(gid, osquery::TEXT_TYPE)
  TABLE_COLUMN(event, osquery::TEXT_TYPE)
  TABLE_COLUMN(exit_code, osquery::TEXT_TYPE)
  TABLE_COLUMN(filename, osquery::TEXT_TYPE)
  TABLE_COLUMN(argv, osquery::TEXT_TYPE)
  TABLE_COLUMN(docker_container_id, osquery::TEXT_TYPE)
END_TABLE(ebpf_process_events)
// clang-format on

struct ProcessEventsSubscriber::PrivateData final {};

ProcessEventsSubscriber::ProcessEventsSubscriber() : d(new PrivateData) {}

osquery::Status ProcessEventsSubscriber::create(
    IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new ProcessEventsSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ProcessEventsSubscriber::~ProcessEventsSubscriber() {}

osquery::Status ProcessEventsSubscriber::initialize() noexcept {
  return osquery::Status(0);
}

void ProcessEventsSubscriber::release() noexcept {}

osquery::Status ProcessEventsSubscriber::configure(
    ProcessEventsPublisher::SubscriptionContextRef subscription_context,
    const json11::Json&) noexcept {
  subscription_context->system_call_filter.insert(__NR_execve);
  subscription_context->system_call_filter.insert(__NR_execveat);
  subscription_context->system_call_filter.insert(KPROBE_FORK_CALL);
  subscription_context->system_call_filter.insert(KPROBE_VFORK_CALL);
  subscription_context->system_call_filter.insert(KPROBE_CLONE_CALL);
  subscription_context->system_call_filter.insert(__NR_exit);
  subscription_context->system_call_filter.insert(__NR_exit_group);

  return osquery::Status(0);
}

osquery::Status ProcessEventsSubscriber::callback(
    osquery::QueryData& new_data,
    ProcessEventsPublisher::SubscriptionContextRef subscription_context,
    ProcessEventsPublisher::EventContextRef event_context) {
  new_data = {};

  for (const auto& event : event_context->probe_event_list) {
    osquery::Row row = {};
    row["timestamp"] = std::to_string(event.timestamp / 1000U);
    row["ppid"] = std::to_string(event.parent_tgid);
    row["pid"] = std::to_string(event.tgid);
    row["tid"] = std::to_string(event.pid);
    row["uid"] = std::to_string(event.uid);
    row["gid"] = std::to_string(event.gid);
    row["event"] = getSystemCallName(event.function_identifier);

    std::string docker_container_id = {};
    auto status =
        getProbeEventField(docker_container_id, event, "docker_container_id");
    if (!status.ok()) {
      row["docker_container_id"] = "";
    } else {
      row["docker_container_id"] = docker_container_id;
    }

    std::string exit_code = {};

    if (event.exit_code) {
      exit_code = std::to_string(event.exit_code.get());
    }

    row["exit_code"] = exit_code;

    if (event.function_identifier == __NR_execve ||
        event.function_identifier == __NR_execveat) {
      std::string filename;
      status = getProbeEventField(filename, event, "filename");
      if (!status.ok()) {
        row["filename"] = "";
      } else {
        row["filename"] = filename;
      }

      ProbeEvent::StringList argv;
      status = getProbeEventField(argv, event, "argv");
      if (!status.ok()) {
        row["argv"] = "";

      } else {
        const auto& argument_list = argv.data;

        std::stringstream buffer;

        for (const auto& argument : argument_list) {
          if (!buffer.str().empty()) {
            buffer << ", ";
          }

          for (const auto& c : argument) {
            if (c == ',') {
              buffer << "\\,";
            } else {
              buffer << c;
            }
          }
        }

        if (argv.truncated) {
          buffer << ", ...";
        }
      }
    }

    new_data.push_back(std::move(row));
  }

  return osquery::Status(0);
}
} // namespace trailofbits
