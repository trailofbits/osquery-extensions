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

#pragma once

#include "managed_probe_generator.h"

#include <pubsub/servicemanager.h>

namespace trailofbits {
struct SystemCallEvent final {
  struct StringList final {
    bool truncated{false};
    std::vector<std::string> data;
  };

  using FieldValue = boost::variant<std::int64_t,
                                    std::uint64_t,
                                    std::string,
                                    std::vector<std::uint8_t>,
                                    StringList>;

  using FieldList = std::map<std::string, FieldValue>;

  std::uint64_t timestamp{0U};
  std::uint64_t syscall_number{0U};
  pid_t pid{0U};
  pid_t tgid{0U};
  uid_t uid{0U};
  gid_t gid{0U};
  boost::optional<int> exit_code;
  FieldList field_list;
};

using SystemCallEventList = std::vector<SystemCallEvent>;

class ManagedProbeReaderService final : public IService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  ManagedProbeReaderService(eBPFProbe& probe, ManagedProbeDescriptor desc);
  virtual ~ManagedProbeReaderService() override;

  virtual osquery::Status initialize() override;
  virtual osquery::Status configure(const json11::Json& configuration);
  virtual void release() override;
  virtual void run() override;

  SystemCallEventList getSystemCallEvents();

 private:
  void processPerfEvents(const std::vector<std::uint32_t>& perf_event_data);
};

using ManagedProbeReaderServiceRef = std::shared_ptr<ManagedProbeReaderService>;
} // namespace trailofbits
