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

#include "ebpfeventsource.h"
#include "ebpfprobepollservice.h"
#include "managed_probe_generator.h"
#include "managedprobereaderservice.h"

namespace trailofbits {
namespace {
// clang-format off
const ManagedProbeDescriptorList kManagedProbeDescriptorList = {
  {
    "close_dup_events", 0U, 0U,

    {
      {
        "sys_enter_close",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "fd"}
        }
      },

      {
        "sys_enter_dup",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "fildes"}
        }
      },

      {
        "sys_enter_dup2",
        {
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "oldfd"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "newfd"}
        }
      },

      {
        "sys_enter_dup3",
        {
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "oldfd"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "newfd"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flags"}
        }
      },

      { "sys_exit_close", {} },
      { "sys_exit_dup", {} },
      { "sys_exit_dup2", {} },
      { "sys_exit_dup3", {} }
    }
  },

  {
    "execve_events", 160U, 10U,

    {
      {
        "sys_enter_execve",
        {
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::StringList, "argv"}
        }
      },

      { "sys_exit_execve", {} }
    }
  },

  {
    "execveat_events", 160U, 10U,

    {
      {
        "sys_enter_execveat",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "fd"},
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::StringList, "argv"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flags"}
        }
      },

      { "sys_exit_execveat", {} }
    }
  },

  // Missing: socketpair, accept, accept4
  {
    "socket_events", 0U, 0U,

    {
      {
        "sys_enter_socket",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "family"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "type"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "protocol"}
        }
      },

      {
        "sys_enter_bind",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "fd" },
          { ManagedProbeTracepoint::Parameter::Type::ByteArray, "umyaddr"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "addrlen" }
        }
      },

      {
        "sys_enter_connect",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "fd" },
          { ManagedProbeTracepoint::Parameter::Type::ByteArray, "uservaddr" },
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "addrlen" }
        }
      },

      { "sys_exit_socket", {} },
      { "sys_exit_bind", {} },
      { "sys_exit_connect", {} }
    }
  }
};
// clang-format on
} // namespace

struct eBPFEventSource::PrivateData final {
  std::vector<eBPFProbeRef> probe_list;
  std::vector<eBPFProbePollServiceRef> poll_service_list;
  std::vector<ManagedProbeReaderServiceRef> reader_service_list;
};

eBPFEventSource::eBPFEventSource() : d(new PrivateData) {
  LOG(INFO) << "eBPF probes will now be generated and compiled. This may use "
               "some CPU";

  for (const auto& desc : kManagedProbeDescriptorList) {
    LOG(INFO) << "Generating probe: " << desc.name;

    eBPFProbeRef probe;
    auto status = generateManagedProbe(probe, desc);
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

    ManagedProbeReaderServiceRef reader_service;
    status =
        ServiceManager::instance().createService<ManagedProbeReaderService>(
            reader_service, *probe.get(), desc);
    if (!status.ok()) {
      throw status;
    }

    d->reader_service_list.push_back(reader_service);

    d->probe_list.push_back(std::move(probe));
    probe.reset();
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

SystemCallEventList eBPFEventSource::getEvents() {
  SystemCallEventList syscall_event_list;

  for (auto& reader_service : d->reader_service_list) {
    auto new_events = reader_service->getSystemCallEvents();

    syscall_event_list.reserve(syscall_event_list.size() + new_events.size());

    syscall_event_list.insert(syscall_event_list.end(),
                              std::make_move_iterator(new_events.begin()),
                              std::make_move_iterator(new_events.end()));
  }

  return syscall_event_list;
}

eBPFEventSource::~eBPFEventSource() {}
} // namespace trailofbits
