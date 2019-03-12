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
#include "probes/kprobe_group/header.h"

#include <map>

#include <asm/unistd_64.h>
#include <fcntl.h>
#include <sys/socket.h>

namespace trailofbits {
namespace {
using ProbeEventHandler = osquery::Status (*)(FileDescriptorTrackerContext&,
                                              const ProbeEvent&);

// clang-format off
const std::map<int, ProbeEventHandler> kProbeEventHandlerMap = {
  { __NR_close, &FileDescriptorTracker::processCloseSyscallEvent },

  { __NR_fcntl, &FileDescriptorTracker::processFcntlSyscallEvent },

  { __NR_dup, &FileDescriptorTracker::processDupSyscallEvent },
  { __NR_dup2, &FileDescriptorTracker::processDupSyscallEvent },
  { __NR_dup3, &FileDescriptorTracker::processDupSyscallEvent },

  { __NR_execve, &FileDescriptorTracker::processExecSyscallEvent },
  { __NR_execveat, &FileDescriptorTracker::processExecSyscallEvent },

  { __NR_socket, &FileDescriptorTracker::processSocketSyscallEvent },

  { __NR_exit, &FileDescriptorTracker::processExitSyscallEvent },
  { __NR_exit_group, &FileDescriptorTracker::processExitSyscallEvent },

  { KPROBE_FORK_CALL, &FileDescriptorTracker::processForkSyscallEvent },
  { KPROBE_VFORK_CALL, &FileDescriptorTracker::processForkSyscallEvent },
  { KPROBE_CLONE_CALL, &FileDescriptorTracker::processForkSyscallEvent }
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

bool FileDescriptorTracker::queryFileDescriptorInformation(
    FileDescriptorInformation& file_descriptor_info,
    pid_t process_id,
    int fd) const {
  return queryFileDescriptorInformation(
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

bool FileDescriptorTracker::queryFileDescriptorInformation(
    FileDescriptorInformation& file_descriptor_info,
    const FileDescriptorTrackerContext& context,
    pid_t process_id,
    int fd) {
  file_descriptor_info = {};

  auto fd_table_it = context.process_to_fd_table_map.find(process_id);
  if (fd_table_it == context.process_to_fd_table_map.end()) {
    return false;
  }

  const auto& fd_table = fd_table_it->second;

  auto fd_info_it = fd_table.find(fd);
  if (fd_info_it == fd_table.end()) {
    return false;
  }

  file_descriptor_info = fd_info_it->second;
  return true;
}

osquery::Status FileDescriptorTracker::processCloseSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  if (probe_event.function_identifier != __NR_close) {
    return osquery::Status::failure("Invalid system call");
  }

  std::int64_t fd = 0;
  auto status = getProbeEventField(fd, probe_event, "fd");
  if (!status.ok()) {
    return status;
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);

  auto fd_it = fd_table.find(fd);
  if (fd_it == fd_table.end()) {
    return osquery::Status::failure("Unknown file descriptor");
  }

  fd_table.erase(fd_it);
  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processFcntlSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  if (probe_event.function_identifier != __NR_fcntl) {
    return osquery::Status::failure("Invalid system call");
  }

  // Get the file descriptor (fcntl uses an unsigned integer!)
  std::int64_t fd = 0;

  {
    std::uint64_t temp_fd = 0;
    auto status = getProbeEventField(temp_fd, probe_event, "fd");
    if (!status.ok()) {
      return status;
    }

    fd = static_cast<std::int64_t>(temp_fd);
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);

  auto fd_it = fd_table.find(fd);
  if (fd_it == fd_table.end()) {
    return osquery::Status::failure("Unknown file descriptor");
  }

  std::uint64_t cmd = 0;
  auto status = getProbeEventField(cmd, probe_event, "cmd");
  if (!status.ok()) {
    return status;
  }

  std::uint64_t arg = 0;
  status = getProbeEventField(arg, probe_event, "arg");
  if (!status.ok()) {
    return status;
  }

  // Actually handle the cmd operation
  auto& fd_information = fd_it->second;

  switch (cmd) {
  case F_DUPFD:
  case F_DUPFD_CLOEXEC: {
    auto new_fd_info = fd_information;
    auto new_fd = probe_event.exit_code.get();

    if (cmd == F_DUPFD_CLOEXEC) {
      new_fd_info.fd_flags |= FD_CLOEXEC;
    }

    fd_table.insert({new_fd, new_fd_info});
    break;
  }

  case F_GETFD: {
    fd_information.fd_flags = probe_event.exit_code.get();
    break;
  }

  case F_SETFD: {
    fd_information.fd_flags = arg;
    break;
  }

  case F_SETFL: {
    if (!fd_information.status_flags_ref) {
      fd_information.status_flags_ref = std::make_shared<FileStatusFlags>();
    }

    fd_information.status_flags_ref->flags = static_cast<int>(arg);
    break;
  }

  case F_GETFL: {
    if (!fd_information.status_flags_ref) {
      fd_information.status_flags_ref = std::make_shared<FileStatusFlags>();
    }

    fd_information.status_flags_ref->flags = probe_event.exit_code.get();
    break;
  }

  default:
    break;
  }

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
    status = getProbeEventField(fd, probe_event, "fildes");
  } else {
    std::uint64_t temp_fd = 0U;
    status = getProbeEventField(temp_fd, probe_event, "oldfd");
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
    status = getProbeEventField(newfd, probe_event, "newfd");
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
    status = getProbeEventField(fd_flags, probe_event, "flags");
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

  std::int64_t family = 0;
  auto status = getProbeEventField(family, probe_event, "family");
  if (!status.ok()) {
    return status;
  }

  std::int64_t type = 0;
  status = getProbeEventField(type, probe_event, "type");

  bool close_on_exec = (type & SOCK_CLOEXEC) != 0;
  bool non_blocking = (type & SOCK_NONBLOCK) != 0;
  type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

  if (!status.ok()) {
    return status;
  }

  std::int64_t protocol = 0;
  status = getProbeEventField(protocol, probe_event, "protocol");
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
  file_desc_info.fd_flags = close_on_exec ? FD_CLOEXEC : 0;

  file_desc_info.status_flags_ref = std::make_shared<FileStatusFlags>();
  file_desc_info.status_flags_ref->flags = non_blocking ? O_NONBLOCK : 0;

  auto socket_fd = probe_event.exit_code.get();

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);
  fd_table.insert({socket_fd, file_desc_info});

  return osquery::Status(0);
}

osquery::Status FileDescriptorTracker::processForkSyscallEvent(
    FileDescriptorTrackerContext& context, const ProbeEvent& probe_event) {
  static const std::set<std::uint64_t> valid_function_id_list = {
      KPROBE_FORK_CALL, KPROBE_VFORK_CALL, KPROBE_CLONE_CALL};

  if (valid_function_id_list.count(probe_event.function_identifier) == 0U) {
    return osquery::Status::failure("Invalid system call");
  }

  std::int64_t host_pid = 0;
  auto status = getProbeEventField(host_pid, probe_event, "host_pid");
  if (!status.ok()) {
    return status;
  }

  auto& fd_table = getFileDescriptorTable(probe_event.tgid, context);
  context.process_to_fd_table_map.insert({host_pid, fd_table});

  return osquery::Status(0);
}
} // namespace trailofbits
