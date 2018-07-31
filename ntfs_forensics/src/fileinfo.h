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
  int type;
  int active;
  flags_t flags;
  uint32_t flag_val;
  int ads;
  size_t size;
  uint64_t inode;
  uint32_t seq;
  uint8_t object_id[16];
  int uid;
  uint32_t gid;
  uint32_t owner_id;
  uint32_t secure_id;
  std::string sid;

  FileInfo();
  std::string getStringRep() const;
};

using FileInfolist = std::list<FileInfo>;

std::string typeNameFromInt(int t);
}