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

#pragma once

#include "probereaderservice.h"

#include <map>
#include <memory>
#include <set>
#include <string>

#include <osquery/status.h>

namespace trailofbits {
using ContainerID = std::string;
using PidList = std::set<pid_t>;

struct DockerContainerInstance final {
  ContainerID id;
  pid_t shim_pid{0};
};

struct DockerTrackerContext final {
  std::map<ContainerID, DockerContainerInstance> docker_container_list;

  std::map<pid_t, ContainerID> process_id_to_container_map;
  std::map<ContainerID, PidList> container_to_pid_list_map;
};

class DockerTracker;
using DockerTrackerRef = std::unique_ptr<DockerTracker>;

class DockerTracker final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  DockerTracker();

 public:
  static osquery::Status create(DockerTrackerRef& object);
  ~DockerTracker();

  void processProbeEvent(ProbeEvent& probe_event);
  bool queryProcessInformation(std::string& container_id, pid_t process_id);
  void cleanupContext();

  enum class Error { Success, Skipped, InvalidEvent, BrokenEvent };

  static Error processContainerShimExecEvent(
      DockerContainerInstance& container_instance,
      const ProbeEvent& probe_event);

  static void processProbeEvent(DockerTrackerContext& context,
                                ProbeEvent& probe_event);

  static bool queryProcessInformation(std::string& container_id,
                                      const DockerTrackerContext& context,
                                      pid_t process_id);

  static void cleanupContext(DockerTrackerContext& context);

  DockerTracker(const DockerTracker&) = delete;
  DockerTracker& operator=(const DockerTracker&) = delete;
};
} // namespace trailofbits
