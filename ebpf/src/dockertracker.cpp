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

#include "dockertracker.h"
#include "probes/kprobe_group/header.h"

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
const char* getDockerTrackerErrorDescription(DockerTracker::Error error) {
  switch (error) {
  case DockerTracker::Error::Success:
    return "The event was recorded";

  case DockerTracker::Error::Skipped:
    return "The event was skipped";

  case DockerTracker::Error::InvalidEvent:
    return "The specified event is not an exec process event";

  case DockerTracker::Error::BrokenEvent:
    return "The containerd-shim invocation was missing one or more parameters";

  default:
    return "<Invalid error code specified>";
  }
}
} // namespace

struct DockerTracker::PrivateData final {
  DockerTrackerContext context;
};

DockerTracker::DockerTracker() : d(new PrivateData) {}

osquery::Status DockerTracker::create(DockerTrackerRef& object) {
  try {
    object.reset();

    auto ptr = new DockerTracker;
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const osquery::Status& status) {
    return status;

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");
  }
}

DockerTracker::~DockerTracker() {}

void DockerTracker::processProbeEvent(ProbeEvent& probe_event) {
  processProbeEvent(d->context, probe_event);
}

bool DockerTracker::queryProcessInformation(std::string& container_id,
                                            pid_t process_id) {
  return queryProcessInformation(container_id, d->context, process_id);
}

void DockerTracker::cleanupContext() {
  cleanupContext(d->context);
}

DockerTracker::Error DockerTracker::processContainerShimExecEvent(
    DockerContainerInstance& container_instance,
    const ProbeEvent& probe_event) {
  static const std::unordered_set<int> kSystemCallFilter = {__NR_execve,
                                                            __NR_execveat};

  container_instance = {};

  if (kSystemCallFilter.count(probe_event.function_identifier) == 0) {
    return Error::InvalidEvent;
  }

  std::string filename = {};
  auto status = getProbeEventField(filename, probe_event, "filename");
  if (!status.ok()) {
    return Error::Skipped;
  }

  auto filename_index = filename.find("/containerd-shim");
  if (filename_index == std::string::npos ||
      filename_index + 16U != filename.size()) {
    return Error::Skipped;
  }

  ProbeEvent::StringList argv;
  status = getProbeEventField(argv, probe_event, "argv");
  if (!status.ok()) {
    return Error::Skipped;
  }

  const auto& argv_string_list = argv.data;

  auto namespace_name_it =
      std::find(argv_string_list.begin(), argv_string_list.end(), "-namespace");

  if (namespace_name_it == argv_string_list.end() ||
      std::next(namespace_name_it, 1) >= argv_string_list.end()) {
    return Error::BrokenEvent;
  }

  auto workdir_it =
      std::find(argv_string_list.begin(), argv_string_list.end(), "-workdir");

  if (workdir_it == argv_string_list.end() ||
      std::next(workdir_it, 1) >= argv_string_list.end()) {
    return Error::BrokenEvent;
  }

  ++namespace_name_it;
  const auto& namespace_name = *namespace_name_it;

  ++workdir_it;
  const auto& workdir = *workdir_it;

  auto container_id_idx = workdir.find("/" + namespace_name + "/");

  if (container_id_idx == std::string::npos ||
      container_id_idx + namespace_name.size() + 2 >= workdir.size()) {
    return Error::BrokenEvent;
  }

  container_id_idx += namespace_name.size() + 2;

  std::string container_id(workdir.c_str() + container_id_idx);
  if (container_id.size() != 64U) {
    return Error::BrokenEvent;
  }

  container_instance.id = container_id;
  container_instance.shim_pid = probe_event.tgid;

  return Error::Success;
}

void DockerTracker::processProbeEvent(DockerTrackerContext& context,
                                      ProbeEvent& probe_event) {
  switch (probe_event.function_identifier) {
  case KPROBE_FORK_CALL:
  case KPROBE_VFORK_CALL:
  case KPROBE_CLONE_CALL: {
    std::string container_id;

    for (auto event_pid : {probe_event.parent_tgid, probe_event.tgid}) {
      auto docker_container_it =
          context.process_id_to_container_map.find(event_pid);

      if (docker_container_it != context.process_id_to_container_map.end()) {
        container_id = docker_container_it->second;
        break;
      }
    }

    if (!container_id.empty()) {
      std::int64_t host_pid = 0;
      auto status = getProbeEventField(host_pid, probe_event, "host_pid");
      if (!status.ok()) {
        VLOG(1) << status.getMessage();

      } else {
        context.process_id_to_container_map.insert({host_pid, container_id});
        context.container_to_pid_list_map[container_id].insert(host_pid);
      }
    }

    break;
  }

  case __NR_execve:
  case __NR_execveat: {
    DockerContainerInstance container_instance;

    auto error = processContainerShimExecEvent(container_instance, probe_event);
    if (error == Error::Success) {
      auto container_id = container_instance.id;

      context.docker_container_list.insert({container_id, container_instance});
      context.container_to_pid_list_map[container_id].insert(probe_event.tgid);
      context.process_id_to_container_map.insert(
          {probe_event.tgid, container_id});

    } else if (error != Error::Skipped) {
      VLOG(1) << getDockerTrackerErrorDescription(error);
    }

    break;
  }

  default:
    break;
  }

  for (auto event_pid : {probe_event.parent_tgid, probe_event.tgid}) {
    std::string container_id = {};

    if (queryProcessInformation(container_id, context, event_pid)) {
      probe_event.field_list.insert({"docker_container_id", container_id});
      break;
    }
  }

  cleanupContext(context);
}

bool DockerTracker::queryProcessInformation(std::string& container_id,
                                            const DockerTrackerContext& context,
                                            pid_t process_id) {
  container_id = {};

  auto it = context.process_id_to_container_map.find(process_id);
  if (it == context.process_id_to_container_map.end()) {
    return false;
  }

  container_id = it->second;
  return true;
}

void DockerTracker::cleanupContext(DockerTrackerContext& context) {
  static const std::string kProcPath{"/proc/"};

  for (auto container_it = context.docker_container_list.begin();
       container_it != context.docker_container_list.end();) {
    const auto& container_info = container_it->second;
    auto path = kProcPath + std::to_string(container_info.shim_pid);

    struct stat dir_stat = {};
    if (stat(path.c_str(), &dir_stat) == 0 && S_ISDIR(dir_stat.st_mode)) {
      ++container_it;
      continue;
    }

    auto pid_list_it =
        context.container_to_pid_list_map.find(container_info.id);
    if (pid_list_it != context.container_to_pid_list_map.end()) {
      auto pid_list = pid_list_it->second;
      context.container_to_pid_list_map.erase(pid_list_it);

      for (auto pid : pid_list) {
        context.process_id_to_container_map.erase(pid);
      }
    }

    LOG(ERROR) << "removed container with id " << container_info.id;
    container_it = context.docker_container_list.erase(container_it);
  }
}
} // namespace trailofbits
