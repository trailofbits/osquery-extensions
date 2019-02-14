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

#include "probereaderservice.h"

#include <unordered_map>

namespace trailofbits {
using ProcessID = std::uint64_t;
using ThreadID = std::uint64_t;

using ProbeEventTracker = std::unordered_map<ThreadID, ProbeEvent>;
using ProbeEventTrackerMap =
    std::unordered_map<std::uint64_t, ProbeEventTracker>;

struct ProcessContext final {
  std::uint64_t process_id{0U};
  ProbeEventTrackerMap event_tracker_map;
};

using ProcessContextMap = std::unordered_map<ProcessID, ProcessContext>;

struct ProbeEventReassemblerContext final {
  ProcessContextMap process_context_map;
};

class ProbeEventReassembler;
using ProbeEventReassemblerRef = std::unique_ptr<ProbeEventReassembler>;

class ProbeEventReassembler final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ProbeEventReassembler();

 public:
  static osquery::Status create(ProbeEventReassemblerRef& obj);
  ~ProbeEventReassembler();

  osquery::Status processProbeEventList(
      ProbeEventList& processed_probe_event_list,
      const ProbeEventList& probe_event_list);
  static osquery::Status processProbeEvent(
      ProbeEventList& processed_probe_event_list,
      ProbeEventReassemblerContext& context,
      const ProbeEvent& probe_event);

  ProbeEventReassembler(const ProbeEventReassembler&) = delete;
  ProbeEventReassembler& operator=(const ProbeEventReassembler&) = delete;
};
} // namespace trailofbits
