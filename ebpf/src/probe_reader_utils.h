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
#include "probes/common/defs.h"

namespace trailofbits {
bool readEventSlot(std::vector<std::uint64_t>& table_data,
                   int& index,
                   std::size_t cpu_id,
                   ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table);

template <typename T>
bool readEventData(T& value,
                   std::vector<std::uint64_t>& table_data,
                   int& index,
                   std::size_t cpu_id,
                   ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table) {
  value = {};

  if (!readEventSlot(table_data, index, cpu_id, event_data_table)) {
    return false;
  }

  value = static_cast<T>(table_data[cpu_id]);
  return true;
}

template <typename BufferType>
bool readEventBuffer(BufferType& value,
                     std::vector<std::uint64_t>& table_data,
                     int& index,
                     std::size_t cpu_id,
                     ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
                     std::size_t string_buffer_size) {
  // clang-format off
  static_assert(
    std::is_same<BufferType, std::string>::value || 
    std::is_same<BufferType, std::vector<std::uint8_t>>::value,
    "Invalid type specified"
  );
  // clang-format on

  value.clear();

  union {
    std::uint64_t chunk;
    char chunk_bytes[8U];
  };

  std::size_t i = 0U;
  auto chunk_count = (string_buffer_size / 8U);

  BufferType new_value;
  new_value.reserve(string_buffer_size);

  auto str_index = index;
  INCREMENT_EVENT_DATA_INDEX_BY(index, chunk_count);

  for (i = 0U; i < chunk_count; ++i) {
    if (!readEventData(
            chunk, table_data, str_index, cpu_id, event_data_table)) {
      return false;
    }

    bool terminate = false;

    for (auto c : chunk_bytes) {
      if (std::is_same<BufferType, std::string>::value) {
        if (c == '\0') {
          terminate = true;
          break;
        }
      }

      new_value.push_back(c);
    }

    if (terminate) {
      break;
    }
  }

  value = std::move(new_value);
  return true;
}

constexpr auto readEventString = &readEventBuffer<std::string>;
constexpr auto readEventByteArray = &readEventBuffer<std::vector<std::uint8_t>>;

bool readEventStringList(
    ProbeEvent::StringList& value,
    std::vector<std::uint64_t>& table_data,
    int& index,
    std::size_t cpu_id,
    ebpf::BPFPercpuArrayTable<std::uint64_t>& event_data_table,
    std::size_t string_buffer_size,
    std::size_t string_list_size);
} // namespace trailofbits
