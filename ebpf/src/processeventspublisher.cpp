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

#include "processeventspublisher.h"
#include "ebpfeventsource.h"
#include "probeeventreassembler.h"
#include "probes/common/defs.h"
#include "probes/kprobe_group/header.h"

#include <iomanip>
#include <iostream>

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
// clang-format off
const std::unordered_map<std::uint64_t, const char*> kSyscallNameTable = {
  { __NR_close, "close" },
  { __NR_dup, "dup" },
  { __NR_dup2, "dup2" },
  { __NR_dup3, "dup3" },
  { __NR_execve, "execve" },
  { __NR_execveat, "execveat" },
  { __NR_socket, "socket" },
  { __NR_bind, "bind" },
  { __NR_connect, "connect" },
  { __NR_fork, "fork" },
  { __NR_vfork, "vfork" },
  { __NR_clone, "clone" },
  { __NR_exit, "exit" },
  { __NR_exit_group, "exit_group" },
  { KPROBE_PIDVNR_CALL, "pid_vnr" },
  { KPROBE_FORK_CALL, "fork" },
  { KPROBE_VFORK_CALL, "vfork" },
  { KPROBE_CLONE_CALL, "clone" },
};
// clang-format on

std::ostream& operator<<(std::ostream& stream, const ProbeEvent& probe_event) {
  static auto L_getEventName =
      [](const ProbeEvent& probe_event) -> const char* {
    auto it = kSyscallNameTable.find(probe_event.function_identifier);
    if (it == kSyscallNameTable.end()) {
      return "<UNKNOWN_SYSCALL_NAME>";
    }

    return it->second;
  };

  stream << std::setfill(' ') << std::setw(16) << probe_event.timestamp << " ";

  stream << std::setfill(' ') << std::setw(8) << probe_event.uid << " ";
  stream << std::setfill(' ') << std::setw(8) << probe_event.gid << " ";
  stream << std::setfill(' ') << std::setw(8) << probe_event.tgid << " ";
  stream << std::setfill(' ') << std::setw(8) << probe_event.pid << " ";
  stream << std::setfill(' ') << std::setw(8) << probe_event.parent_tgid << " ";

  stream << std::setfill(' ') << std::setw(8) << probe_event.function_identifier
         << " ";

  stream << std::setfill(' ') << std::setw(16) << L_getEventName(probe_event)
         << "(";

  bool add_separator = false;
  for (const auto& field : probe_event.field_list) {
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

      stream << "{ ";

      auto byte_count = std::min(value.size(), 4UL);
      bool truncated = value.size() > byte_count;

      for (auto i = 0U; i < byte_count; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex
               << static_cast<std::uint32_t>(value.at(i)) << " ";
      }

      if (truncated) {
        stream << "... ";
      }

      stream << "}";
      break;
    }

    case 4U: {
      const auto& value = boost::get<ProbeEvent::StringList>(field.second);
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

  if (probe_event.exit_code) {
    stream << " -> " << probe_event.exit_code.get();
  }

  return stream;
}

bool compareProbeEvents(const ProbeEvent& lhs, const ProbeEvent& rhs) {
  return lhs.timestamp < rhs.timestamp;
}
} // namespace

struct ProcessEventsPublisher::PrivateData final {
  eBPFEventSourceRef event_source;
  ProbeEventReassemblerRef event_reassembler;
};

ProcessEventsPublisher::ProcessEventsPublisher() : d(new PrivateData) {
  auto status = eBPFEventSource::create(d->event_source);
  if (!status.ok()) {
    throw status;
  }

  status = ProbeEventReassembler::create(d->event_reassembler);
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status ProcessEventsPublisher::create(IEventPublisherRef& publisher) {
  try {
    auto ptr = new ProcessEventsPublisher();
    publisher.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

osquery::Status ProcessEventsPublisher::initialize() noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::release() noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onConfigurationChangeStart(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onConfigurationChangeEnd(
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::onSubscriberConfigurationChange(
    const json11::Json&, SubscriberType&, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::updatePublisher() noexcept {
  // Acquire the unprocessed events
  auto unprocessed_event_list = d->event_source->getEvents();
  if (unprocessed_event_list.empty()) {
    return osquery::Status(0);
  }

  std::sort(unprocessed_event_list.begin(),
            unprocessed_event_list.end(),
            compareProbeEvents);

  // Generate the new events
  ProbeEventList processed_event_list;

  for (const auto& probe_event : unprocessed_event_list) {
    auto status = d->event_reassembler->processProbeEvent(processed_event_list,
                                                          probe_event);
    if (!status.ok()) {
      LOG(ERROR) << "An error has occurred while the reassembled events were "
                    "being processed: "
                 << status.getMessage();
    }
  }

  if (processed_event_list.empty()) {
    return osquery::Status(0);
  }

  EventContextRef event_context;
  auto status = createEventContext(event_context);
  if (!status.ok()) {
    return status;
  }

  std::stringstream buffer;
  for (const auto& event : processed_event_list) {
    buffer.str("");
    buffer << event;

    event_context->string_list.push_back(buffer.str());
  }

  broadcastEvent(event_context);

  return osquery::Status(0);
}

osquery::Status ProcessEventsPublisher::updateSubscriber(
    IEventSubscriberRef, SubscriptionContextRef) noexcept {
  return osquery::Status(0);
}
} // namespace trailofbits
