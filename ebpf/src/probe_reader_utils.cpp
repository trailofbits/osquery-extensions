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

#include "probe_reader_utils.h"

#include <osquery/logger.h>

namespace trailofbits {
bool readEventSlot(std::vector<std::uint64_t>& table_data,
                   int& index,
                   std::size_t cpu_id,
                   ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table) {
  table_data.clear();

  auto status = event_data_table.get_value(index, table_data);
  if (status.code() != 0) {
    LOG(ERROR) << "Read has failed: " << status.msg();
    return false;
  }

  if (cpu_id >= table_data.size()) {
    LOG(ERROR) << "Invalid CPU index: " << cpu_id;
    return false;
  }

  INCREMENT_EVENT_DATA_INDEX(index);
  return true;
}

bool readEventStringList(
    ProbeEvent::StringList& value,
    std::vector<std::uint64_t>& table_data,
    int& index,
    std::size_t cpu_id,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t string_buffer_size,
    std::size_t string_list_size) {
  value = {};

  for (std::size_t string_index = 0U; string_index < string_list_size;
       string_index++) {
    std::uint64_t next_qword;
    auto temp_index = index;
    if (!readEventData(
            next_qword, table_data, temp_index, cpu_id, event_data_table)) {
      return false;
    }

    if (next_qword == VARARGS_TRUNCATION) {
      value.truncated = true;
      index = temp_index;
      break;

    } else if (next_qword == VARARGS_TERMINATOR) {
      value.truncated = false;
      index = temp_index;
      break;
    }

    std::string str = {};
    if (!readEventString(str,
                         table_data,
                         index,
                         cpu_id,
                         event_data_table,
                         string_buffer_size)) {
      return false;
    }

    value.data.push_back(std::move(str));
  }

  return true;
}
} // namespace trailofbits
