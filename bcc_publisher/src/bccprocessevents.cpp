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

#include "bccprocessevents.h"

namespace trailofbits {
// clang-format off
BEGIN_TABLE(bcc_process_events)
  TABLE_COLUMN(type, osquery::TEXT_TYPE)
  TABLE_COLUMN(timestamp, osquery::TEXT_TYPE)
  TABLE_COLUMN(pid, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid_ns1, osquery::TEXT_TYPE)
  TABLE_COLUMN(childpid_ns2, osquery::TEXT_TYPE)
  TABLE_COLUMN(filename, osquery::TEXT_TYPE)
  TABLE_COLUMN(argv, osquery::TEXT_TYPE)
END_TABLE(bcc_process_events)
// clang-format on

struct BCCProcessEvents::PrivateData final {};

BCCProcessEvents::BCCProcessEvents() : d(new PrivateData) {}

osquery::Status BCCProcessEvents::create(IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new BCCProcessEvents();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

BCCProcessEvents::~BCCProcessEvents() {}

osquery::Status BCCProcessEvents::initialize() noexcept {
  return osquery::Status(0);
}

void BCCProcessEvents::release() noexcept {}

osquery::Status BCCProcessEvents::configure(
    BCCProcessEventsPublisher::SubscriptionContextRef,
    const json11::Json&) noexcept {
  return osquery::Status(0);
}

osquery::Status BCCProcessEvents::callback(
    osquery::QueryData& new_data,
    BCCProcessEventsPublisher::SubscriptionContextRef,
    BCCProcessEventsPublisher::EventContextRef event_context) {
  new_data = {};

  for (const auto& process_event : event_context->event_list) {
    osquery::Row row = {};

    if (process_event.type == ProcessEvent::Type::Exec) {
      row["type"] = "exec";
    } else {
      row["type"] = "fork";
    }

    row["timestamp"] = std::to_string(process_event.timestamp);
    row["pid"] = std::to_string(process_event.pid);

    if (process_event.type == ProcessEvent::Type::Exec) {
      row["childpid"] = "";
      row["childpid_ns1"] = "";
      row["childpid_ns2"] = "";

      const auto& data = boost::get<ProcessEvent::ExecData>(process_event.data);

      row["filename"] = data.filename;

      std::stringstream buffer;
      for (const auto& str : data.arguments) {
        if (!buffer.str().empty()) {
          buffer << ", ";
        }

        buffer << "\"";

        // Probably not foolproof
        for (const auto c : str) {
          if (c == '"') {
            buffer << "\\\"";
          } else {
            buffer << c;
          }
        }

        buffer << "\"";
      }

      row["argv"] = buffer.str();

    } else {
      row["filename"] = "";
      row["argv"] = "";

      const auto& data = boost::get<ProcessEvent::ForkData>(process_event.data);

      row["childpid"] = std::to_string(data.child_pid);

      if (data.child_pid_namespaced.size() >= 1) {
        row["childpid_ns1"] = std::to_string(data.child_pid_namespaced.at(0));
      } else {
        row["childpid_ns1"] = "";
      }

      if (data.child_pid_namespaced.size() >= 2) {
        row["childpid_ns2"] = std::to_string(data.child_pid_namespaced.at(1));
      } else {
        row["childpid_ns2"] = "";
      }
    }

    new_data.push_back(std::move(row));
  }

  return osquery::Status(0);
}
} // namespace trailofbits
