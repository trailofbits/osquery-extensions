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

#include "bcc_probe_generator.h"

#include <pubsub/servicemanager.h>

#include <set>

namespace trailofbits {
struct ProbeEvent final {
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
  std::uint64_t event_identifier{0U};
  std::uint64_t function_identifier{0U};
  pid_t pid{0U};
  pid_t tgid{0U};
  pid_t parent_tgid{0U};
  uid_t uid{0U};
  gid_t gid{0U};
  boost::optional<int> exit_code;
  FieldList field_list;
};

using ProbeEventList = std::vector<ProbeEvent>;

class ProbeReaderService final : public IService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  ProbeReaderService(eBPFProbe& probe, ManagedTracepointProbe desc);
  ProbeReaderService(eBPFProbe& probe, KprobeProbe desc);

  virtual ~ProbeReaderService() override;

  virtual osquery::Status initialize() override;
  virtual osquery::Status configure(const json11::Json& configuration);
  virtual void release() override;
  virtual void run() override;

  ProbeEventList getProbeEvents();

 private:
  void processPerfEvents(const std::vector<std::uint32_t>& perf_event_data);
};

using ProbeReaderServiceRef = std::shared_ptr<ProbeReaderService>;
} // namespace trailofbits
