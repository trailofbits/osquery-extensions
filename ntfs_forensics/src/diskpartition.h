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

#include <boost/noncopyable.hpp>

#include <tsk/libtsk.h>

#include "diskdevice.h"
#include "ntfs_types.h"
#include "ntfsdirectoryindexentry.h"
#include "ntfsfileinformation.h"

namespace trailofbits {
/// Describes a partition that exists in a disk device
struct DiskPartitionInformation final {
  /// This is the device name, in the "\\.\PhysicalDrive0" form
  std::string device;

  /// The partition number
  std::uint32_t part_address;

  /// The partition description; it usually contains the file system name
  std::string descriptor;
};

/// A list of disk partitions
using DiskPartitionInformationList = std::list<DiskPartitionInformation>;

class DiskPartition;
using DiskPartitionRef = std::shared_ptr<DiskPartition>;

/// This class wraps the TSK volume information object, while also offering
/// several utilities to inspect the file system
class DiskPartition final : private boost::noncopyable {
  /// Constructs a new object by opening the specified partition from the
  /// given device. Will throw an osquery::Status object in case of error
  DiskPartition(std::shared_ptr<DiskDevice> device,
                std::uint32_t partition_index);

 public:
  /// Constructs a new object, by opening the specified partition from
  /// the given device. This function never throws an exception
  static osquery::Status create(DiskPartitionRef& partition,
                                DiskDeviceRef device,
                                std::uint32_t partition_index) noexcept;

  /// Destructor
  ~DiskPartition();

  /// Queries the file system for information about the specified path
  int getFileInfo(const std::string& path, NTFSFileInformation& results);

  /// Queries the file system for information about the specified inode
  int getFileInfo(uint64_t inode, NTFSFileInformation& results);

  /// Walks the whole partition recursively
  void walkPartition(void (*callback)(NTFSFileInformation&, void*),
                     void* context);

  /// Performs a recursive scan of the specified directory
  void recurseDirectory(void (*callback)(NTFSFileInformation&, void*),
                        void* context,
                        const std::string& path,
                        int depth);

  /// Collects the index entries from the specified folder
  void collectINDX(const std::string& path, DirEntryList& entries);

  /// Collects the index entries from the specified folder inode
  void collectINDX(uint64_t inode, DirEntryList& entries);

  /// Collects the index entries from the specified folder object
  void collectINDX(TSK_FS_FILE* fsFile, DirEntryList& entries);

 private:
  /// Performs a recursive scan of the specified directory. This is a helper for
  /// the following two public methods: walkPartition, recurseDirectory
  void recurseDirectory(void (*callback)(NTFSFileInformation&, void*),
                        void* context,
                        const std::string& path,
                        TSK_FS_DIR* dir,
                        uint64_t parent,
                        int depth,
                        std::unordered_set<uint64_t>& processed);

  int getFileInfo(TSK_FS_FILE* file,
                  NTFSFileInformation& results,
                  bool collect_parent_path = true);

  int collectPath(uint64_t inode, std::stringstream& path);

  /// The disk containing this partition
  std::shared_ptr<DiskDevice> disk_device;

  TSK_VS_INFO* volInfo{nullptr};
  const TSK_VS_PART_INFO* vsPartInfo{nullptr};
  TSK_FS_INFO* fsInfo{nullptr};
};

/// Collects basic info for all partitions for all devices on the system.
DiskPartitionInformationList getPartitionList();
}
