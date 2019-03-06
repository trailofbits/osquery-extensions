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

#include <memory>

#include <osquery/status.h>

namespace trailofbits {
class FileDescriptorTracker;
using FileDescriptorTrackerRef = std::unique_ptr<FileDescriptorTracker>;

struct FileDescriptorInformation final {
  enum class Type { File, Socket };

  struct FileData final {
    std::string path;
  };

  struct SocketData final {
    int family{0};
    int type{0};
    int protocol{0};
  };

  Type type;
  boost::variant<FileData, SocketData> data;

  int fd_flags{0};
};

using FileDescriptorTable = std::unordered_map<int, FileDescriptorInformation>;

struct FileDescriptorTrackerContext final {
  std::unordered_map<pid_t, FileDescriptorTable> process_to_fd_table_map;
};

class FileDescriptorTracker final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  FileDescriptorTracker();

 public:
  static osquery::Status create(FileDescriptorTrackerRef& object);
  ~FileDescriptorTracker();

  osquery::Status processProbeEvent(const ProbeEvent& probe_event);

  bool querytFileDescriptorInformation(
      FileDescriptorInformation& file_descriptor_info,
      pid_t process_id,
      int fd) const;

  static osquery::Status processProbeEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);

  static bool querytFileDescriptorInformation(
      FileDescriptorInformation& file_descriptor_info,
      const FileDescriptorTrackerContext& context,
      pid_t process_id,
      int fd);

  static osquery::Status processCloseSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);
  static osquery::Status processDupSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);
  static osquery::Status processExecSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);
  static osquery::Status processExitSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);
  static osquery::Status processSocketSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);
  static osquery::Status processForkSyscallEvent(
      FileDescriptorTrackerContext& context, const ProbeEvent& probe_event);

  FileDescriptorTracker(const FileDescriptorTracker&) = delete;
  FileDescriptorTracker& operator=(const FileDescriptorTracker&) = delete;
};
} // namespace trailofbits
