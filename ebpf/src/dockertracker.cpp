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

osquery::Status DockerTracker::processProbeEvent(
    const ProbeEvent& probe_event) {
  return processProbeEvent(d->context, probe_event);
}

bool DockerTracker::queryProcessInformation(std::string& container_id,
                                            pid_t process_id) {
  return queryProcessInformation(container_id, d->context, process_id);
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
  return Error::Success;
}

osquery::Status DockerTracker::processProbeEvent(
    DockerTrackerContext& context, const ProbeEvent& probe_event) {
  switch (probe_event.function_identifier) {
  case KPROBE_FORK_CALL:
  case KPROBE_VFORK_CALL:
  case KPROBE_CLONE_CALL: {
    auto docker_container_it =
        context.process_id_to_container_map.find(probe_event.tgid);

    if (docker_container_it == context.process_id_to_container_map.end()) {
      return osquery::Status(0);
    }

    const auto& container_id = docker_container_it->second;

    std::int64_t host_pid = 0;
    auto status = getProbeEventField(host_pid, probe_event, "host_pid");
    if (!status.ok()) {
      return status;
    }

    context.process_id_to_container_map.insert({host_pid, container_id});
    context.container_to_pid_list_map[container_id].insert(host_pid);

    return osquery::Status(0);
  }

  case __NR_execve:
  case __NR_execveat: {
    DockerContainerInstance container_instance;
    auto error = processContainerShimExecEvent(container_instance, probe_event);
    if (error == Error::Skipped) {
      return osquery::Status(0);

    } else if (error != Error::Success) {
      return osquery::Status::failure(getDockerTrackerErrorDescription(error));
    }

    auto container_id = container_instance.id;
    context.docker_container_list.insert(
        {container_id, std::move(container_instance)});

    context.container_to_pid_list_map[container_id].insert(probe_event.tgid);

    context.process_id_to_container_map.insert(
        {probe_event.tgid, std::move(container_id)});

    return osquery::Status(0);
  }

  case __NR_exit:
  case __NR_exit_group: {
    auto docker_container_it =
        context.process_id_to_container_map.find(probe_event.tgid);

    if (docker_container_it == context.process_id_to_container_map.end()) {
      return osquery::Status(0);
    }

    const auto& container_id = docker_container_it->second;
    context.process_id_to_container_map.erase(docker_container_it);

    auto pid_list_it = context.container_to_pid_list_map.find(container_id);
    if (pid_list_it == context.container_to_pid_list_map.end()) {
      return osquery::Status::failure(
          "Failed to locate the container pid list");
    }

    auto& pid_list = pid_list_it->second;
    pid_list.erase(probe_event.tgid);

    if (pid_list.empty()) {
      context.container_to_pid_list_map.erase(container_id);
      context.docker_container_list.erase(container_id);
    }

    return osquery::Status(0);
  }

  default:
    break;
  }

  return osquery::Status(0);
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
} // namespace trailofbits
