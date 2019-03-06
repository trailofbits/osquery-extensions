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

#include "filedescriptortracker.h"

#include <map>

#include <asm/unistd_64.h>

namespace trailofbits {
namespace {
using ProbeEventHandler = osquery::Status (*)(FileDescriptorTrackerContext&,
                                              const ProbeEvent&);

// clang-format off
const std::map<int, ProbeEventHandler> kProbeEventHandlerMap = {
  { __NR_close, &FileDescriptorTracker::processCloseSyscallEvent },

  { __NR_dup, &FileDescriptorTracker::processDupSyscallEvent },
  { __NR_dup2, &FileDescriptorTracker::processDupSyscallEvent },
  { __NR_dup3, &FileDescriptorTracker::processDupSyscallEvent },

  { __NR_execve, &FileDescriptorTracker::processExecSyscallEvent },
  { __NR_execveat, &FileDescriptorTracker::processExecSyscallEvent },

  { __NR_socket, &FileDescriptorTracker::processSocketSyscallEvent },

  { __NR_exit, &FileDescriptorTracker::processExitSyscallEvent },
  { __NR_exit_group, &FileDescriptorTracker::processExitSyscallEvent },

  { __NR_close, &FileDescriptorTracker::processForkSyscallEvent }
};
// clang-format on

FileDescriptorTable& getFileDescriptorTable(
    pid_t process_id, FileDescriptorTrackerContext& context) {
  auto fd_table_it = context.process_to_fd_table_map.find(process_id);
  if (fd_table_it == context.process_to_fd_table_map.end()) {
    auto p = context.process_to_fd_table_map.insert({process_id, {}});
    fd_table_it = p.first;
  }

  return fd_table_it->second;
}

bool getFileDescriptorInformation(FileDescriptorInformation*& fd_info_ptr,
                                  pid_t process_id,
                                  int fd,
                                  FileDescriptorTrackerContext& context,
                                  FileDescriptorTable* fd_table_ptr = nullptr) {
  if (fd_table_ptr == nullptr) {
    fd_table_ptr = &getFileDescriptorTable(process_id, context);
  }

  auto& fd_table = *fd_table_ptr;

  auto fd_info_it = fd_table.find(fd);
  if (fd_info_it == fd_table.end()) {
    return false;
  }

  fd_info_ptr = &fd_info_it->second;
  return true;
}

template <typename IntegerType>
osquery::Status getProbeEventIntegerField(IntegerType& value,
                                          const ProbeEvent& probe_event,
                                          const std::string& name) {
  auto field_var_it = probe_event.field_list.find(name);
  if (field_var_it == probe_event.field_list.end()) {
    return osquery::Status::failure("The following parameter is missing: " +
                                    name);
  }

  const auto& field_var = field_var_it->second;
  value = boost::get<IntegerType>(field_var);

  return osquery::Status(0);
}
} // namespace

struct FileDescriptorTracker::PrivateData final {
  FileDescriptorTrackerContext context;
};

FileDescriptorTracker::FileDescriptorTracker() : d(new PrivateData) {}

osquery::Status FileDescriptorTracker::create(
    FileDescriptorTrackerRef& object) {
  try {
    object.reset();

    auto ptr = new FileDescriptorTracker();
    object.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

FileDescriptorTracker::~FileDescriptorTracker() {}

osquery::Status FileDescriptorTracker::processProbeEvent(
    const ProbeEvent& probe_event) {
  return processProbeEvent(d->context, probe_event);
}

bool FileDescriptorTracker::querytFileDescriptorInformation(
    FileDescriptorInformation& file_descriptor_info,
    pid_t process_id,
    int fd) const {
  return querytFileDescriptorInformation(
      file_descriptor_info, d->context, process_id, fd);
}

osquery::Status FileDescriptorTracker::processProbeEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  auto handler_it = kProbeEventHandlerMap.find(probe_event.function_identifier);
  if (handler_it == kProbeEventHandlerMap.end()) {
    return osquery::Status(0);
  }

  auto& handler = handler_it->second;
  return handler(context, probe_event);
}

bool FileDescriptorTracker::querytFileDescriptorInformation(
    FileDescriptorInformation& file_descriptor_info,
    const FileDescriptorTrackerContext& context,
    pid_t process_id,
    int fd) {
  file_descriptor_info = {};

  return true;
}

osquery::Status FileDescriptorTracker::processCloseSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  if (probe_event.function_identifier != __NR_close) {
    return osquery::Status::failure("Invalid system call");
  }

  auto fd_var_it = probe_event.field_list.find("fd");
  if (fd_var_it == probe_event.field_list.end()) {
    return osquery::Status::failure("The fd parameter is missing");
  }

  const auto& fd_var = fd_var_it->second;
  auto fd = boost::get<std::int64_t>(fd_var);

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);

  auto fd_it = fd_table.find(fd);
  if (fd_it == fd_table.end()) {
    return osquery::Status::failure("Unknown file descriptor");
  }

  fd_table.erase(fd_it);
  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processDupSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  static const std::set<int> valid_function_id_list = {
      __NR_dup, __NR_dup2, __NR_dup3};
  if (valid_function_id_list.count(probe_event.function_identifier) == 0U) {
    return osquery::Status::failure("Invalid system call");
  }

  if (probe_event.exit_code.get() == -1) {
    return osquery::Status(0);
  }

  std::int64_t fd = 0;

  osquery::Status status;
  if (probe_event.function_identifier == __NR_dup) {
    status = getProbeEventIntegerField(fd, probe_event, "fildes");
  } else {
    std::uint64_t temp_fd = 0U;
    status = getProbeEventIntegerField(temp_fd, probe_event, "oldfd");
    fd = static_cast<std::int64_t>(temp_fd);
  }

  if (!status.ok()) {
    return status;
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);

  FileDescriptorInformation* existing_fd_info_ptr = nullptr;
  if (!getFileDescriptorInformation(
          existing_fd_info_ptr, probe_event.tgid, fd, context)) {
    return osquery::Status::failure("Unknown file descriptor");
  }

  auto created_fd_info = *existing_fd_info_ptr;
  auto created_fd = probe_event.exit_code.get();

  if (probe_event.function_identifier == __NR_dup2 ||
      probe_event.function_identifier == __NR_dup3) {
    std::int64_t newfd = 0;
    auto status = getProbeEventIntegerField(newfd, probe_event, "newfd");
    if (!status.ok()) {
      return status;
    }

    auto newfd_it = fd_table.find(newfd);
    if (newfd_it != fd_table.end()) {
      fd_table.erase(newfd_it);
    }
  }

  if (probe_event.function_identifier == __NR_dup3) {
    std::int64_t fd_flags = 0;
    auto status = getProbeEventIntegerField(fd_flags, probe_event, "flags");
    if (!status.ok()) {
      return status;
    }

    created_fd_info.fd_flags = fd_flags;
  }

  fd_table.insert({created_fd, created_fd_info});
  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processExecSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  static const std::set<int> valid_function_id_list = {__NR_execve,
                                                       __NR_execveat};
  if (valid_function_id_list.count(probe_event.function_identifier) == 0U) {
    return osquery::Status::failure("Invalid system call");
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);
  for (auto fd_it = fd_table.begin(); fd_it != fd_table.end();) {
    const auto& fd_info = fd_it->second;

    if ((fd_info.fd_flags & FD_CLOEXEC) != 0) {
      fd_it = fd_table.erase(fd_it);
    } else {
      ++fd_it;
    }
  }

  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processExitSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  static const std::set<int> valid_function_id_list = {__NR_exit,
                                                       __NR_exit_group};
  if (valid_function_id_list.count(probe_event.function_identifier) == 0U) {
    return osquery::Status::failure("Invalid system call");
  }

  auto proc_it = context.process_to_fd_table_map.find(probe_event.tgid);
  if (proc_it == context.process_to_fd_table_map.end()) {
    return osquery::Status::failure("Unknown process id");
  }

  context.process_to_fd_table_map.erase(proc_it);
  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processSocketSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  if (probe_event.function_identifier != __NR_socket) {
    return osquery::Status::failure("Invalid system call");
  }

  return osquery::Status(0);

  std::int64_t family = 0;
  auto status = getProbeEventIntegerField(family, probe_event, "family");
  if (!status.ok()) {
    return status;
  }

  std::int64_t type = 0;
  status = getProbeEventIntegerField(type, probe_event, "type");
  if (!status.ok()) {
    return status;
  }

  std::int64_t protocol = 0;
  status = getProbeEventIntegerField(protocol, probe_event, "protocol");
  if (!status.ok()) {
    return status;
  }

  FileDescriptorInformation::SocketData socket_data;
  socket_data.family = family;
  socket_data.type = type;
  socket_data.protocol = protocol;

  FileDescriptorInformation file_desc_info;
  file_desc_info.type = FileDescriptorInformation::Type::Socket;
  file_desc_info.data = socket_data;
  file_desc_info.fd_flags = 0;

  auto socket_fd = probe_event.exit_code.get();

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);
  fd_table.insert({socket_fd, file_desc_info});

  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processForkSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  static const std::set<int> valid_function_id_list = {
      __NR_fork, __NR_vfork, __NR_clone};
  if (valid_function_id_list.count(probe_event.function_identifier) == 0U) {
    return osquery::Status::failure("Invalid system call");
  }

  std::int64_t host_pid = 0;
  auto status = getProbeEventIntegerField(host_pid, probe_event, "host_pid");
  if (!status.ok()) {
    return status;
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);
  context.process_to_fd_table_map.insert({host_pid, fd_table});

  return osquery::Status(0);
}
} // namespace trailofbits
