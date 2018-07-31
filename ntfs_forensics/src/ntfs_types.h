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

#include <cstdint>
#include <list>
#include <string>

namespace trailofbits {

struct ntfs_mft_file_reference_t final {
  uint64_t inode{0U};
  uint32_t sequence{0U};
};

struct timestamp_t final {
  uint64_t btime{0U};
  uint64_t mtime{0U};
  uint64_t ctime{0U};
  uint64_t atime{0U};
};

struct flags_t final {
  bool read_only{false};
  bool hidden{false};
  bool system{false};
  bool archive{false};
  bool device{false};
  bool normal{false};
  bool temporary{false};
  bool sparse{false};
  bool reparse_point{false};
  bool compressed{false};
  bool offline{false};
  bool unindexed{false};
  bool encrypted{false};
};
}
