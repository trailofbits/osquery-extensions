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
#include "managedprobeservice.h"

namespace trailofbits {
namespace {
using ManagedProbeDescriptorList = std::vector<ManagedProbeDescriptor>;

// clang-format off
const ManagedProbeDescriptorList kManagedProbeDescriptorList = {
  {
    "open_events", 256U, 0U,

    {
      {
        "sys_enter_open",
        {
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flags"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "mode"}
        }
      },

      {
        "sys_enter_openat",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "dfd"},
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flags"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "mode"}
        }
      },

      {
        // TODO(alessandro): struct file_handle
        "sys_enter_open_by_handle_at",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "mountdirfd"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flags"}
        }
      },

      {
        // TODO(alessandro): struct file_handle, mnt_id
        "sys_enter_name_to_handle_at",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "dfd"},
          { ManagedProbeTracepoint::Parameter::Type::String, "name"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "flag"}
        }
      },

      { "sys_exit_open", {} },
      { "sys_exit_openat", {} },
      { "sys_exit_open_by_handle_at", {} },
      { "sys_exit_name_to_handle_at", {} }
    }
  },

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

  {
    "create_mkdnod_events", 160U, 0U,

    {
      {
        "sys_enter_creat",
        {
          { ManagedProbeTracepoint::Parameter::Type::String, "pathname"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "mode"}
        }
      },

      {
        "sys_enter_mknod",
        {
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "mode"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "dev"}
        }
      },

      {
        "sys_enter_mknodat",
        {
          { ManagedProbeTracepoint::Parameter::Type::String, "filename"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "mode"},
          { ManagedProbeTracepoint::Parameter::Type::UnsignedInteger, "dev"}
        }
      },

      { "sys_exit_creat", {} },
      { "sys_exit_mknod", {} },
      { "sys_exit_mknodat", {} }
    }
  },

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
        // TODO(alessandro): usockvec
        "sys_enter_socketpair",
        {
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "family"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "type"},
          { ManagedProbeTracepoint::Parameter::Type::SignedInteger, "protocol"}
        }
      },

      { "sys_exit_socket", {} },
      { "sys_exit_socketpair", {} }
    }
  }
};
// clang-format on
} // namespace

struct eBPFEventSource::PrivateData final {
  std::vector<ManagedProbeRef> probe_list;
  std::vector<ManagedProbeServiceRef> service_list;
};

eBPFEventSource::eBPFEventSource() : d(new PrivateData) {
  for (const auto& desc : kManagedProbeDescriptorList) {
    LOG(INFO) << "Generating probe: " << desc.name;

    ManagedProbeRef probe;
    auto status = trailofbits::ManagedProbe::create(probe, desc);
    if (!status.ok()) {
      throw status;
    }

    ManagedProbeServiceRef service;
    status = ServiceManager::instance().createService<ManagedProbeService>(
        service, *probe.get());
    if (!status.ok()) {
      throw status;
    }

    d->probe_list.push_back(std::move(probe));
    probe.reset();

    d->service_list.push_back(service);
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
  SystemCallEventList new_events;

  for (auto& probe : d->probe_list) {
    auto probe_events = probe->getEvents();

    new_events.reserve(new_events.size() + probe_events.size());

    new_events.insert(new_events.end(),
                      std::make_move_iterator(probe_events.begin()),
                      std::make_move_iterator(probe_events.end()));
  }

  return new_events;
}

eBPFEventSource::~eBPFEventSource() {}
} // namespace trailofbits
