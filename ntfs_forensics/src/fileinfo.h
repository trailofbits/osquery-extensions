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

#include "ntfs_types.h"
#include "ntfsfilenameattributecontents.h"

namespace trailofbits {
struct FileInfo final {
  std::string name;
  std::string path;
  std::string parent_path;
  timestamp_t standard_info_times;
  ntfs_filename_attribute_contents_t filename;
  flags_t flags;
  std::string sid;

  int type{0};
  int active{0};
  uint32_t flag_val{0U};
  int ads{0};
  size_t size{0U};
  uint64_t inode{0U};
  uint32_t seq{0U};
  uint8_t object_id[16]{0U};
  int uid{0};
  uint32_t gid{0U};
  uint32_t owner_id{0U};
  uint32_t secure_id{0U};

  std::string getStringRep() const;
};

using FileInfolist = std::list<FileInfo>;

std::string typeNameFromInt(int t);
}