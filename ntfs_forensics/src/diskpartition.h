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
#include <memory>
#include <string>
#include <unordered_set>

#include <tsk/libtsk.h>

#include "diskdevice.h"
#include "ntfs_types.h"
#include "ntfsdirectoryindexentry.h"
#include "ntfsfileinformation.h"

namespace trailofbits {
struct DiskPartitionInformation final {
  std::string device;
  std::uint32_t part_address{0U};
  std::string descriptor;
};

using DiskPartitionInformationList = std::list<DiskPartitionInformation>;

class DiskPartition final {
 public:
  explicit DiskPartition(std::shared_ptr<DiskDevice> device,
                         std::uint32_t partition_index);
  ~DiskPartition();

  int getFileInfo(const std::string& path, NTFSFileInformation& results);
  int getFileInfo(uint64_t inode, NTFSFileInformation& results);

  void walkPartition(void (*callback)(NTFSFileInformation&, void*),
                     void* context);
  void recurseDirectory(void (*callback)(NTFSFileInformation&, void*),
                        void* context,
                        const std::string& path,
                        TSK_FS_DIR* dir,
                        uint64_t parent,
                        int depth,
                        std::unordered_set<uint64_t>& processed);

  void recurseDirectory(void (*callback)(NTFSFileInformation&, void*),
                        void* context,
                        const std::string& path,
                        int depth);

  void collectINDX(const std::string& path, DirEntryList&);
  void collectINDX(uint64_t inode, DirEntryList&);

  void collectINDX(TSK_FS_FILE* fsFile, DirEntryList&);

 private:
  int getFileInfo(TSK_FS_FILE* file,
                  NTFSFileInformation& results,
                  bool collect_parent_path = true);

  int collectPath(uint64_t inode, std::stringstream& path);

  std::shared_ptr<DiskDevice> disk_device;
  TSK_VS_INFO* volInfo{nullptr};
  const TSK_VS_PART_INFO* vsPartInfo{nullptr};
  TSK_FS_INFO* fsInfo{nullptr};
};

/// Collects basic info for all partitions for all devices on the system.
DiskPartitionInformationList getPartitionList();
}
