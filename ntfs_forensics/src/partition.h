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

#include <list>
#include <string>
#include <unordered_set>

#include <tsk/libtsk.h>

#include "device.h"
#include "fileinfo.h"
#include "ntfs_types.h"
#include "ntfsdirectoryindexentry.h"

namespace trailofbits {
struct PartInfo {
  std::string device;
  unsigned int part_address{0U};
  std::string descriptor;
};

using PartInfoList = std::list<PartInfo>;

class Partition final {
 public:
  explicit Partition(Device& device, int partition_index);
  ~Partition();

  int getFileInfo(const std::string& path, FileInfo& results);
  int getFileInfo(uint64_t inode, FileInfo& results);

  void walkPartition(void (*callback)(FileInfo&, void*), void* context);
  void recurseDirectory(void (*callback)(FileInfo&, void*),
                        void* context,
                        std::string* path,
                        TSK_FS_DIR* dir,
                        uint64_t parent,
                        int depth,
                        std::unordered_set<uint64_t>& processed);

  void recurseDirectory(void (*callback)(FileInfo&, void*),
                        void* context,
                        std::string* path,
                        int depth);

  void collectINDX(const std::string& path, DirEntryList&);
  void collectINDX(uint64_t inode, DirEntryList&);

  void collectINDX(TSK_FS_FILE* fsFile, DirEntryList&);

 private:
  int getFileInfo(TSK_FS_FILE* file,
                  FileInfo& results,
                  bool collect_parent_path = true);
  int collectPath(uint64_t inode, std::stringstream& path);

  TSK_VS_INFO* volInfo;
  const TSK_VS_PART_INFO* vsPartInfo;
  TSK_FS_INFO* fsInfo;
};

void getPartInfo(PartInfoList& results);
}
