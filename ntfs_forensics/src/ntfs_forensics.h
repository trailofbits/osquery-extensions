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
#include <sstream>
#include <string>
#include <unordered_set>

#include <tsk/libtsk.h>
namespace trailofbits {

typedef struct ntfs_timestamp_struct {
  uint64_t btime;
  uint64_t mtime;
  uint64_t ctime;
  uint64_t atime;

  ntfs_timestamp_struct() : btime(0), mtime(0), ctime(0), atime(0) {}
} timestamp_t;

typedef struct ntfs_mft_file_reference {
  uint64_t inode;
  uint32_t sequence;
  ntfs_mft_file_reference() : inode(0), sequence(0) {}
} ntfs_mft_file_reference_t;

typedef struct ntfs_flags_struct {
  bool read_only;
  bool hidden;
  bool system;
  bool archive;
  bool device;
  bool normal;
  bool temporary;
  bool sparse;
  bool reparse_point;
  bool compressed;
  bool offline;
  bool unindexed;
  bool encrypted;
} flags_t;

typedef struct ntfs_filename_attribute_contents {
  ntfs_mft_file_reference_t parent;
  timestamp_t file_name_times;
  uint64_t allocated_size;
  uint64_t real_size;
  uint32_t flags;
  uint8_t name_length;
  std::string filename;

  bool valid() const;
  ntfs_filename_attribute_contents();
} ntfs_filename_attribute_contents_t;

struct FileInfo {
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

typedef std::list<FileInfo> FileInfoList;

struct PartInfo {
  std::string device;
  unsigned int part_address;
  std::string descriptor;
};

typedef std::list<PartInfo> PartInfoList;

typedef struct ntfs_directory_index_entry {
  ntfs_mft_file_reference_t mft_ref;
  uint16_t entry_length;
  uint16_t name_length;
  uint32_t flags;
  uint64_t child_vcn;

  ntfs_filename_attribute_contents_t filename;
  uint32_t slack_addr;

  ntfs_directory_index_entry();
  std::string getStringRep() const;
  bool valid() const;
} ntfs_directory_index_entry_t;

typedef std::list<trailofbits::ntfs_directory_index_entry_t> DirEntryList;

std::string typeNameFromInt(int t);

void getPartInfo(PartInfoList& results);

class Partition;

class Device {
 public:
  explicit Device(const std::string& dev_name);
  ~Device();

 private:
  TSK_IMG_INFO* imgInfo;
  friend class Partition;
};

class Partition {
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
}
