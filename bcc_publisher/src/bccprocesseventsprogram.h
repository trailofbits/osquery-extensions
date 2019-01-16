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

#include "bccprocesseventsprogramtypes.h"
#include "probes/common/utilities.h"

#include <BPF.h>

namespace trailofbits {
class BCCProcessEventsProgram;
using BCCProcessEventsProgramRef = std::unique_ptr<BCCProcessEventsProgram>;

class BCCProcessEventsProgram final {
  BCCProcessEventsProgram();

  void detachProbes();

 protected:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  void processPerfEvent(
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      const std::uint32_t* event_identifiers,
      std::size_t event_identifier_count);

 public:
  static osquery::Status create(BCCProcessEventsProgramRef& object);
  ~BCCProcessEventsProgram();

  osquery::Status initialize();
  ProcessEventList getEvents();

  template <typename T>
  static void readSyscallEventData(
      T& value,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index) {
    value = {};

    std::vector<std::uint64_t> table_data = {};
    auto status = event_data_table.get_value(current_index, table_data);
    if (status.code() != 0) {
      throw osquery::Status::failure(status.msg());
    }

    if (cpu_index >= table_data.size()) {
      throw osquery::Status::failure("Invalid CPU index");
    }

    value = static_cast<T>(table_data[cpu_index]);
    INCREMENT_EVENT_DATA_INDEX(current_index);
  }

  static osquery::Status readSyscallEventHeader(
      SyscallEvent::Header& event_header,
      int& current_index,
      std::size_t& cpu_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::uint32_t event_identifier);

  static osquery::Status readSyscallEventString(
      std::string& string_data,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventExecData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventCloneData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventExitData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventPidVnrData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventCreatData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventMknodData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventMknodatData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventOpenData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventOpenatData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventOpenByHandleAtData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventNameToHandleAtData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventCloseData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventDupData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventDup2Data(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventDup3Data(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventSocketData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEventSocketPairData(
      SyscallEvent& syscall_event,
      int& current_index,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::size_t cpu_index);

  static osquery::Status readSyscallEvent(
      SyscallEvent& event,
      ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
      std::uint32_t event_identifier);

  static osquery::Status processSyscallEvent(ProcessEvent& process_event,
                                             BCCProcessEventsContext& context,
                                             const SyscallEvent& syscall_event);

  BCCProcessEventsProgram(const BCCProcessEventsProgram& other) = delete;
  BCCProcessEventsProgram& operator=(const BCCProcessEventsProgram& other) =
      delete;
};
} // namespace trailofbits
