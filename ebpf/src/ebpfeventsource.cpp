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

#include "ebpfeventsource.h"
#include "bcc_probe_generator.h"
#include "ebpfprobepollservice.h"
#include "probeeventreassembler.h"

#include <bcc_probe_kprobe_group.h>
#include <probes/kprobe_group/header.h>

namespace trailofbits {
namespace {
// Missing: socketpair, accept, accept4
// clang-format off
const ManagedTracepointProbeList kManagedProbeDescriptorList = {
  {
    "close_events", 0U, 0U,

    {
      {
        "sys_enter_close",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "fd" }
        }
      },

      { "sys_exit_close", false, {} },
    }
  },

  {
    "dup_events", 0U, 0U,

    {
      {
        "sys_enter_dup",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "fildes" }
        }
      },

      {
        "sys_enter_dup2",
        true,
        {
          { ProbeParameter::Type::UnsignedInteger, "oldfd" },
          { ProbeParameter::Type::UnsignedInteger, "newfd" }
        }
      },

      {
        "sys_enter_dup3",
        true,
        {
          { ProbeParameter::Type::UnsignedInteger, "oldfd" },
          { ProbeParameter::Type::UnsignedInteger, "newfd" },
          { ProbeParameter::Type::SignedInteger, "flags" }
        }
      },

      { "sys_exit_dup", false, {} },
      { "sys_exit_dup2", false, {} },
      { "sys_exit_dup3", false, {} }
    }
  },

  {
    "execve_events", 160U, 10U,

    {
      {
        "sys_enter_execve",
        true,
        {
          { ProbeParameter::Type::String, "filename" },
          { ProbeParameter::Type::StringList, "argv" }
        }
      },

      { "sys_exit_execve", false, {} }
    }
  },

  {
    "execveat_events", 160U, 10U,

    {
      {
        "sys_enter_execveat",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "fd" },
          { ProbeParameter::Type::String, "filename" },
          { ProbeParameter::Type::StringList, "argv" },
          { ProbeParameter::Type::SignedInteger, "flags" }
        }
      },

      { "sys_exit_execveat", false, {} }
    }
  },

  {
    "exit_events", 0U, 0U,

    {
      { "sys_enter_exit",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "error_code" }
        }
      },

      { "sys_enter_exit_group",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "error_code" }
        }
      },
    }
  },

  {
    "socket_events", 160U, 0U,

    {
      {
        "sys_enter_socket",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "family" },
          { ProbeParameter::Type::SignedInteger, "type" },
          { ProbeParameter::Type::SignedInteger, "protocol" }
        }
      },

      {
        "sys_enter_bind",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "fd" },
          { ProbeParameter::Type::ByteArray, "umyaddr"},
          { ProbeParameter::Type::SignedInteger, "addrlen" }
        }
      },

      {
        "sys_enter_connect",
        true,
        {
          { ProbeParameter::Type::SignedInteger, "fd" },
          { ProbeParameter::Type::ByteArray, "uservaddr" },
          { ProbeParameter::Type::SignedInteger, "addrlen" }
        }
      },

      { "sys_exit_socket", false, {} },
      { "sys_exit_bind", false, {} },
      { "sys_exit_connect", false, {} }
    }
  }
};
// clang-format on

// clang-format off
const KprobeProbeList kKprobeList = {
  {
    "kprobe_group",
    kBccProbe_kprobe_group,

    {
      {
        "pid_vnr",
        false,
        true,
        {
          { ProbeParameter::Type::SignedInteger, "pid_count" },
          { ProbeParameter::Type::SignedInteger, "host_pid" },
          { ProbeParameter::Type::SignedInteger, "pid1" },
          { ProbeParameter::Type::SignedInteger, "pid2" }
        }
      },

      { "fork", true, true, { } },
      { "fork", true, false, { } },

      { "vfork", true, true, { } },
      { "vfork", true, false, { } },

      {
        "clone",
        true,
        true,
        {
          { ProbeParameter::Type::SignedInteger, "clone_flags" }
        }
      },
      
      { "clone", true, false, { } }
    }
  }
};
// clang-format on
} // namespace

struct eBPFEventSource::PrivateData final {
  std::vector<eBPFProbeRef> probe_list;
  std::vector<eBPFProbePollServiceRef> poll_service_list;
  std::vector<ProbeReaderServiceRef> reader_service_list;

  ProbeEventReassemblerRef event_reassembler;
};

eBPFEventSource::eBPFEventSource() : d(new PrivateData) {
  LOG(INFO) << "eBPF probes will now be generated and compiled. This may use "
               "some CPU";

  for (const auto& desc : kKprobeList) {
    LOG(INFO) << "Generating kprobe for: " << desc.name;

    eBPFProbeRef probe;
    auto status = generateKprobeProbe(probe, desc);
    if (!status.ok()) {
      throw status;
    }

    eBPFProbePollServiceRef poll_service;
    status = ServiceManager::instance().createService<eBPFProbePollService>(
        poll_service, *probe.get());
    if (!status.ok()) {
      throw status;
    }

    d->poll_service_list.push_back(poll_service);

    ProbeReaderServiceRef reader_service;
    status = ServiceManager::instance().createService<ProbeReaderService>(
        reader_service, *probe.get(), desc);
    if (!status.ok()) {
      throw status;
    }

    d->reader_service_list.push_back(reader_service);

    d->probe_list.push_back(std::move(probe));
    probe.reset();
  }

  for (const auto& desc : kManagedProbeDescriptorList) {
    LOG(INFO) << "Generating tracepoint probe for: " << desc.name;

    eBPFProbeRef probe;
    auto status = generateManagedTracepointProbe(probe, desc);
    if (!status) {
      throw status;
    }

    eBPFProbePollServiceRef poll_service;
    status = ServiceManager::instance().createService<eBPFProbePollService>(
        poll_service, *probe.get());
    if (!status.ok()) {
      throw status;
    }

    d->poll_service_list.push_back(poll_service);

    ProbeReaderServiceRef reader_service;
    status = ServiceManager::instance().createService<ProbeReaderService>(
        reader_service, *probe.get(), desc);
    if (!status.ok()) {
      throw status;
    }

    d->reader_service_list.push_back(reader_service);

    d->probe_list.push_back(std::move(probe));
    probe.reset();
  }

  auto status = ProbeEventReassembler::create(d->event_reassembler);
  if (!status.ok()) {
    throw status;
  }
}

osquery::Status eBPFEventSource::create(eBPFEventSourceRef& object) {
  try {
    object.reset();

    auto ptr = new eBPFEventSource();
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ProbeEventList eBPFEventSource::getEvents() {
  ProbeEventList probe_event_list;

  for (auto& reader_service : d->reader_service_list) {
    auto new_event_list = reader_service->getProbeEvents();

    // clang-format off
    std::sort(
      new_event_list.begin(),
      new_event_list.end(),

      [](const ProbeEvent& lhs, const ProbeEvent& rhs) -> bool {
        return lhs.timestamp < rhs.timestamp;
      }
    );
    // clang-format on

    probe_event_list.reserve(probe_event_list.size() + new_event_list.size());

    probe_event_list.insert(probe_event_list.end(),
                            std::make_move_iterator(new_event_list.begin()),
                            std::make_move_iterator(new_event_list.end()));
  }

  // Generate the new events
  ProbeEventList processed_event_list;

  for (const auto& probe_event : probe_event_list) {
    auto status = d->event_reassembler->processProbeEvent(processed_event_list,
                                                          probe_event);
    if (!status.ok()) {
      LOG(ERROR) << "An error has occurred while the reassembled events were "
                    "being processed: "
                 << status.getMessage();
    }
  }

  return processed_event_list;
}

eBPFEventSource::~eBPFEventSource() {}
} // namespace trailofbits
