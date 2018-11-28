#pragma once

#include "bccprocesseventsprogramtypes.h"

#include <osquery/sdk.h>

#include <map>
#include <set>
#include <string>

namespace trailofbits {
using ContainerID = std::string;

using PidList = std::set<pid_t>;

struct DockerContainerInstance final {
  std::string namespace_name;
  ContainerID container_id;
  std::string workdir;
};

struct DockerState final {
  /// This is the list of Docker containers that are currently running
  std::map<ContainerID, DockerContainerInstance> docker_container_list;

  /// Maps
  std::map<pid_t, ContainerID> process_id_to_container_map;

  std::map<ContainerID, PidList> container_to_pid_list_map;
};

class DockerTracker final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  DockerTracker();
  ~DockerTracker();

  osquery::Status processEvent(ProcessEvent& process_event);

  enum class Error { Success, Skipped, InvalidEvent, BrokenEvent };

  static Error parseContainerShimExecEvent(
      DockerContainerInstance& container_instance,
      const ProcessEvent& process_event);
  static osquery::Status updateDockerState(DockerState& docker_state,
                                           const ProcessEvent& process_event);
};
} // namespace trailofbits
