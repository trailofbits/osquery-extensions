#include "dockertracker.h"

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
  DockerState docker_state;
};

DockerTracker::DockerTracker() : d(new PrivateData) {}

DockerTracker::~DockerTracker() {}

osquery::Status DockerTracker::processEvent(ProcessEvent& process_event) {
  process_event.docker_container_id.clear();
  process_event.docker_namespace_name.clear();

  auto status = updateDockerState(d->docker_state, process_event);
  if (!status.ok()) {
    return status;
  }

  auto container_id_it =
      d->docker_state.process_id_to_container_map.find(process_event.tgid);
  if (container_id_it == d->docker_state.process_id_to_container_map.end()) {
    return osquery::Status(0);
  }

  const auto& container_id = container_id_it->second;

  auto container_instance_it =
      d->docker_state.docker_container_list.find(container_id);
  if (container_instance_it == d->docker_state.docker_container_list.end()) {
    return osquery::Status(0);
  }

  auto& container_instance = container_instance_it->second;

  process_event.docker_container_id = container_instance.container_id;
  process_event.docker_namespace_name = container_instance.namespace_name;

  return osquery::Status(0);
}

DockerTracker::Error DockerTracker::parseContainerShimExecEvent(
    DockerContainerInstance& container_instance,
    const ProcessEvent& process_event) {
  container_instance = {};

  if (process_event.type != ProcessEvent::Type::Exec) {
    return Error::InvalidEvent;
  }

  const auto& exec_data =
      boost::get<ProcessEvent::ExecData>(process_event.data);

  if (exec_data.exit_code != 0) {
    return Error::Skipped;
  }

  if (exec_data.filename.find("containerd-shim") == std::string::npos) {
    return Error::Skipped;
  }

  auto namespace_name_it = std::find(
      exec_data.arguments.begin(), exec_data.arguments.end(), "-namespace");
  if (namespace_name_it == exec_data.arguments.end() ||
      std::next(namespace_name_it, 1) >= exec_data.arguments.end()) {
    return Error::BrokenEvent;
  }

  auto workdir_it = std::find(
      exec_data.arguments.begin(), exec_data.arguments.end(), "-workdir");
  if (workdir_it == exec_data.arguments.end() ||
      std::next(workdir_it, 1) >= exec_data.arguments.end()) {
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

  container_instance.namespace_name = namespace_name;
  container_instance.container_id = container_id;
  container_instance.workdir = workdir;

  return Error::Success;
}

osquery::Status DockerTracker::updateDockerState(
    DockerState& docker_state, const ProcessEvent& process_event) {
  switch (process_event.type) {
  case ProcessEvent::Type::Fork: {
    auto docker_container_it =
        docker_state.process_id_to_container_map.find(process_event.tgid);
    if (docker_container_it == docker_state.process_id_to_container_map.end()) {
      return osquery::Status(0);
    }

    const auto& container_id = docker_container_it->second;

    const auto& fork_data =
        boost::get<ProcessEvent::ForkData>(process_event.data);

    docker_state.process_id_to_container_map.insert(
        {fork_data.child_pid, container_id});

    docker_state.container_to_pid_list_map[container_id].insert(
        fork_data.child_pid);

    return osquery::Status(0);
  }

  case ProcessEvent::Type::Exec: {
    DockerContainerInstance container_instance;
    auto error = parseContainerShimExecEvent(container_instance, process_event);
    if (error == Error::Skipped) {
      return osquery::Status(0);
    } else if (error != Error::Success) {
      return osquery::Status::failure(getDockerTrackerErrorDescription(error));
    }

    auto container_id = container_instance.container_id;
    docker_state.docker_container_list.insert(
        {container_id, std::move(container_instance)});

    docker_state.container_to_pid_list_map[container_id].insert(
        process_event.tgid);

    docker_state.process_id_to_container_map.insert(
        {process_event.tgid, std::move(container_id)});

    return osquery::Status(0);
  }

  case ProcessEvent::Type::Exit: {
    auto docker_container_it =
        docker_state.process_id_to_container_map.find(process_event.tgid);
    if (docker_container_it == docker_state.process_id_to_container_map.end()) {
      return osquery::Status(0);
    }

    auto container_id = docker_container_it->second;
    if (docker_state.container_to_pid_list_map.count(container_id) == 0 ||
        docker_state.docker_container_list.count(container_id) == 0) {
      return osquery::Status::failure("Internal error");
    }

    auto& container_pid_list =
        docker_state.container_to_pid_list_map[container_id];

    container_pid_list.erase(process_event.tgid);
    if (container_pid_list.size() == 0U) {
      docker_state.container_to_pid_list_map.erase(container_id);
      docker_state.docker_container_list.erase(container_id);
    }

    docker_state.process_id_to_container_map.erase(process_event.tgid);
    return osquery::Status(0);
  }

  default:
    return osquery::Status::failure("Invalid event type");
  }

  return osquery::Status(0);
}
} // namespace trailofbits
