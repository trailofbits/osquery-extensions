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

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
// Missing: socketpair, accept, accept4
// clang-format off
const ManagedTracepointProbeList kManagedProbeDescriptorList = {
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
      VLOG(1) << "An error has occurred while the reassembled events were "
                 "being processed: "
              << status.getMessage();

      continue;
    }
  }

  return processed_event_list;
}

eBPFEventSource::~eBPFEventSource() {}
} // namespace trailofbits
