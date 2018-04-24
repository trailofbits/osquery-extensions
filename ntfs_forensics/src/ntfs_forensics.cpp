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

#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ntfs_forensics.h"

#include <tsk/base/tsk_base_i.h>

namespace trailofbits {

void processAttrs(TSK_FS_FILE* fsFile, FileInfo& result);

FileInfo::FileInfo()
    : type(0),
      active(0),
      flag_val(0),
      ads(0),
      size(0),
      inode(0),
      seq(0),
      uid(0),
      gid(0),
      owner_id(0),
      secure_id(0) {
  memset(object_id, 0, sizeof(object_id));
}

std::string FileInfo::getStringRep() const {
  // for ease of debugging
  std::stringstream output;

  output << "name: \"" << this->name << "\"\n"
         << "path: \"" << this->path << "\"\n"
         << "parent: " << this->filename.parent.inode << ","
         << this->filename.parent.sequence << "\n"
         << "btime:    " << this->standard_info_times.btime << "\n"
         << "mtime:    " << this->standard_info_times.mtime << "\n"
         << "ctime:    " << this->standard_info_times.ctime << "\n"
         << "atime:    " << this->standard_info_times.atime << "\n"
         << "fn_btime: " << this->filename.file_name_times.btime << "\n"
         << "fn_mtime: " << this->filename.file_name_times.mtime << "\n"
         << "fn_ctime: " << this->filename.file_name_times.ctime << "\n"
         << "fn_atime: " << this->filename.file_name_times.atime << "\n"
         << "type: " << typeNameFromInt(this->type) << "\n"
         << "active: " << (this->active > 0 ? "true" : "false") << "\n";

  std::stringstream flags, fn_flags;
  flags << "0x" << std::hex << std::setfill('0') << std::setw(8)
        << this->flag_val;
  fn_flags << "0x" << std::hex << std::setfill('0') << std::setw(8)
           << this->filename.flags;

  output << "flags: " << flags.str() << "\nfn_flags: " << fn_flags.str() << "\n"
         << "ads: " << (this->ads == 0 ? "false" : "true") << "\n"
         << "allocated: " << this->filename.allocated_size << "\n"
         << "size:      " << this->filename.real_size << "\n"
         << "inode: " << this->inode << "\n"
         << "seq: " << this->seq << "\n"
         << "uid: " << this->uid << "\n"
         << "gid: " << this->gid << "\n"
         << "owner_id: " << this->owner_id << "\n"
         << "sid: " << this->sid << "\n";

  std::stringstream oid;
  for (int i = 0; i < 16; ++i) {
    oid << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(this->object_id[i]);
  }

  output << "object_id: " << oid.str() << "\n";
  return output.str();
}

ntfs_filename_attribute_contents::ntfs_filename_attribute_contents()
    : allocated_size(0), real_size(0), flags(0), name_length(0) {}

ntfs_directory_index_entry::ntfs_directory_index_entry()
    : entry_length(0), name_length(0), flags(0), child_vcn(0), slack_addr(0) {}

std::string ntfs_directory_index_entry::getStringRep() const {
  std::stringstream output;
  output << "inode: " << this->mft_ref.inode << "\n"
         << "seq: " << this->mft_ref.sequence << "\n"
         << "entry_length: " << this->entry_length << "\n"
         << "name_length: " << this->name_length << "\n"
         << "flags: " << this->flags << "\n"
         << "filename: "
         << (name_length > 0 ? this->filename.filename : "(no name)") << "\n"
         << "child_vcn: " << this->child_vcn << "\n"
         << "slack_addr: " << this->slack_addr << "\n";
  return output.str();
}

uint32_t unixtimestamp(uint64_t ntdate) {
#define NSEC_BTWN_1601_1970 (uint64_t)(116444736000000000ULL)

  ntdate -= (uint64_t)NSEC_BTWN_1601_1970;
  ntdate /= (uint64_t)10000000;

  return (uint32_t)ntdate;
}

bool ntfs_filename_attribute_contents::valid() const {
  uint32_t unix_1990 = 631152000;
  uint32_t unix_2025 = 1735689600;

  return (unix_2025 > unixtimestamp(file_name_times.atime)) &&
         (unixtimestamp(file_name_times.atime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.btime)) &&
         (unixtimestamp(file_name_times.btime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.ctime)) &&
         (unixtimestamp(file_name_times.ctime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.mtime)) &&
         (unixtimestamp(file_name_times.mtime) > unix_1990);
}

bool ntfs_directory_index_entry::valid() const {
  return filename.valid() && entry_length >= 0x52 && entry_length < 4096 &&
         flags < 4 && child_vcn < 4096 && name_length < 4096;
}

template <typename T>
void uintFromBuffer(const uint8_t* data, int64_t offset, T& result) {
  result = *(reinterpret_cast<const T*>(&data[offset]));
}

void processFlags(uint32_t f, flags_t& flags) {
  flags.read_only = f & 0x0001 ? true : false;
  flags.hidden = f & 0x0002 ? true : false;
  flags.system = f & 0x0004 ? true : false;
  flags.archive = f & 0x0020 ? true : false;
  flags.device = f & 0x0040 ? true : false;
  flags.normal = f & 0x0080 ? true : false;
  flags.temporary = f & 0x0100 ? true : false;
  flags.sparse = f & 0x0200 ? true : false;
  flags.reparse_point = f & 0x0400 ? true : false;
  flags.compressed = f & 0x0800 ? true : false;
  flags.offline = f & 0x1000 ? true : false;
  flags.unindexed = f & 0x2000 ? true : false;
  flags.encrypted = f & 0x4000 ? true : false;
}

void processFileReference(const uint8_t* data,
                          ntfs_mft_file_reference_t& parent) {
  parent.inode = 0;
  parent.sequence = 0;
  uint64_t raw_val = *(reinterpret_cast<const uint64_t*>(data));
  parent.inode = raw_val & 0xFFFFFFFFFFFF;
  parent.sequence = (raw_val >> 32) & 0xFFFF;
}

void processFileNameBuffer(const uint8_t* data,
                           ntfs_filename_attribute_contents_t& filename,
                           size_t size) {
  processFileReference(data, filename.parent);
  uintFromBuffer(data, 8, filename.file_name_times.btime);
  uintFromBuffer(data, 16, filename.file_name_times.mtime);
  uintFromBuffer(data, 24, filename.file_name_times.ctime);
  uintFromBuffer(data, 32, filename.file_name_times.atime);
  uintFromBuffer(data, 40, filename.allocated_size);
  uintFromBuffer(data, 48, filename.real_size);
  filename.flags = *(reinterpret_cast<const uint32_t*>(&data[56]));
  uintFromBuffer(data, 64, filename.name_length);

  if (filename.valid() && (size >= (66 + (2 * filename.name_length)))) {
    const UTF16* filename_start = (const UTF16*)(data + 66);
    UTF16* filename_end = (UTF16*)(data + 66 + (filename.name_length * 2));
    unsigned char* buffer = new unsigned char[size];
    unsigned char* backup_ptr = buffer;
    memset(buffer, 0, size);
    char* buf_ptr = (char*)buffer;
    if (TSKconversionOK == tsk_UTF16toUTF8(TSK_LIT_ENDIAN,
                                           &filename_start,
                                           filename_end,
                                           &buffer,
                                           buffer + size,
                                           TSKlenientConversion)) {
      filename.filename = std::string(buf_ptr);
    } else {
      filename.filename = std::string("(bad UTF16 conversion)");
    }
    delete[] backup_ptr;
  }
}

void processFileNameAttrib(const TSK_FS_ATTR* attrib, FileInfo& results) {
  // bytes	description
  //  0 -  7	file reference of parent dir
  //  8 - 15	file creation time
  // 16 - 23	file modification time
  // 24 - 31	MFT modification time
  // 32 - 39	File access time
  // 40 - 47	Allocated size of file
  // 48 - 55	Real size of file
  if (attrib->rd.buf_size >= 60) {
    const uint8_t* data = attrib->rd.buf;
    processFileNameBuffer(data, results.filename, attrib->rd.buf_size);
  }
}

void processObjectIdAttrib(const TSK_FS_ATTR* attrib, FileInfo& result) {
  // bytes	description
  //  0 - 15	object id
  // 16 - 31	birth volume id
  // 32 - 47	birth object id
  // 48 - 63	birth domain id
  if (attrib->rd.buf_size >= 16) {
    memcpy(result.object_id, attrib->rd.buf, 16);
  }
}

void processStandardAttrib(const TSK_FS_ATTR* attrib, FileInfo& results) {
  // bytes	description
  //  0 -  7	file creation time
  //  8 - 15	file altered time
  // 16 - 23	MFT modification time
  // 24 - 31	File access time
  // 32 - 35	Flags
  // ...
  // 48 - 51	Owner ID
  // 52 - 55	Security ID
  if (attrib->rd.buf_size >= 56) {
    const uint8_t* data = attrib->rd.buf;
    uintFromBuffer(data, 0, results.standard_info_times.btime);
    uintFromBuffer(data, 8, results.standard_info_times.mtime);
    uintFromBuffer(data, 16, results.standard_info_times.ctime);
    uintFromBuffer(data, 24, results.standard_info_times.atime);
    results.flag_val = *(reinterpret_cast<const uint32_t*>(&data[32]));
    processFlags(results.flag_val, results.flags);
    uintFromBuffer(data, 48, results.owner_id);
    uintFromBuffer(data, 52, results.secure_id);
  }
}

void processAttrs(TSK_FS_FILE* fsFile, FileInfo& results) {
  int dataAttribCount = 0;
  for (int i = 0; i < tsk_fs_file_attr_getsize(fsFile); ++i) {
    const TSK_FS_ATTR* attrib = tsk_fs_file_attr_get_idx(fsFile, i);
    if (attrib != NULL) {
      switch (attrib->type) {
      case 48:
        processFileNameAttrib(attrib, results);
        break;
      case 16:
        processStandardAttrib(attrib, results);
        break;
      case 64:
        processObjectIdAttrib(attrib, results);
        break;
      case 128:
        // data attribute, track for ADS
        ++dataAttribCount;
        break;
      }
    }
  }
  results.ads = (dataAttribCount > 1 ? 1 : 0);
}

int Partition::collectPath(uint64_t inode, std::stringstream& path_str) {
  int rval = -1;
  TSK_FS_FILE* fsFile = tsk_fs_file_open_meta(fsInfo, NULL, inode);
  if (rval == NULL) {
    return -1;
  }

  ntfs_mft_file_reference_t parent;
  rval = -1;
  for (int i = 0; i < tsk_fs_file_attr_getsize(fsFile); ++i) {
    const TSK_FS_ATTR* attrib = tsk_fs_file_attr_get_idx(fsFile, i);
    if (attrib != NULL && attrib->type == 48) {
      processFileReference(attrib->rd.buf, parent);
      rval = 0;
      break;
    }
  }

  // if we failed to collect the directory name
  // or if we're at the root directory, we're done
  if (parent.inode == inode || rval != 0) {
    tsk_fs_file_close(fsFile);
    return rval;
  }

  TSK_FS_META* fsMeta = fsFile->meta;
  if (fsMeta == NULL || fsMeta->name2 == NULL) {
    return -1;
  }

  std::string path_element = std::string(fsMeta->name2->name);

  tsk_fs_file_close(fsFile);

  rval = collectPath(parent.inode, path_str);

  path_str << "/" << path_element;

  return rval;
}

/* Collects basic info for all partitions for all devices on the system. */
void getPartInfo(PartInfoList& results) {
  results.clear();
  for (unsigned int i = 0;; ++i) {
    std::stringstream device;
    device << "\\\\.\\PhysicalDrive" << i;
    TskImgInfo imgInfo;
    int rval = imgInfo.open(device.str().c_str(), TSK_IMG_TYPE_DETECT, 0);
    if (rval != 0) {
      break;
    } // assuming that all physical drives are contiguously numbered

    TskVsInfo volInfo;
    rval = volInfo.open(&imgInfo, 0, TSK_VS_TYPE_DETECT);
    if (rval != 0) {
      continue;
    }

    for (unsigned int partIdx = 0; partIdx < volInfo.getPartCount();
         ++partIdx) {
      const TskVsPartInfo* vsPartInfo = volInfo.getPart(partIdx);
      if (vsPartInfo != NULL) {
        results.push_back({device.str(),
                           vsPartInfo->getAddr(),
                           std::string(vsPartInfo->getDesc())});
      }
      delete vsPartInfo;
    }
  }
}

std::string typeNameFromInt(int t) {
  switch (t) {
  case TSK_FS_META_TYPE_UNDEF:
    return std::string("Undefined");
    break;
  case TSK_FS_META_TYPE_REG:
    return std::string("File");
    break;
  case TSK_FS_META_TYPE_DIR:
    return std::string("Directory");
    break;
  }
  return std::string("Unknown");
}

Device::Device(const std::string& device) : imgInfo(NULL) {
  const char* paths[1];
  paths[0] = device.c_str();
  imgInfo = tsk_img_open_utf8(1, paths, TSK_IMG_TYPE_DETECT, 0);
  if (imgInfo == NULL) {
    throw std::runtime_error("unable to open device");
  }
}

Device::~Device() {
  tsk_img_close(imgInfo);
}

Partition::Partition(Device& device, int partition_index)
    : volInfo(NULL), vsPartInfo(NULL), fsInfo(NULL) {
  volInfo = tsk_vs_open(device.imgInfo, 0, TSK_VS_TYPE_DETECT);
  if (volInfo == NULL) {
    throw std::runtime_error("unable to open volume");
  }

  vsPartInfo = tsk_vs_part_get(volInfo, partition_index);
  if (vsPartInfo == NULL) {
    throw std::runtime_error("unable to open partition");
  }

  fsInfo = tsk_fs_open_vol(vsPartInfo, TSK_FS_TYPE_DETECT);
  if (fsInfo == NULL) {
    throw std::runtime_error("unable to open filesystem");
  }
}

Partition::~Partition() {
  tsk_fs_close(fsInfo);
  tsk_vs_close(volInfo);
}

int Partition::getFileInfo(const std::string& path, FileInfo& results) {
  int rval = 0;

  TSK_FS_FILE* fsFile = tsk_fs_file_open(fsInfo, NULL, path.c_str());

  if (fsFile == NULL) {
    return 6;
  }

  rval = getFileInfo(fsFile, results);
  tsk_fs_file_close(fsFile);
  return rval;
}

int Partition::getFileInfo(uint64_t inode, FileInfo& results) {
  int rval = 0;
  TSK_FS_FILE* fsFile = tsk_fs_file_open_meta(fsInfo, NULL, inode);
  if (fsFile == NULL) {
    return 6;
  }
  rval = getFileInfo(fsFile, results);

  tsk_fs_file_close(fsFile);

  return rval;
}

int Partition::getFileInfo(TSK_FS_FILE* fsFile,
                           FileInfo& results,
                           bool collect_parent_path) {
  TSK_FS_META* fsMeta = fsFile->meta;
  if (fsMeta != NULL) {
    results.inode = fsMeta->addr;
    results.seq = fsMeta->seq;
    results.gid = fsMeta->gid;
    results.uid = fsMeta->uid;
    results.type = fsMeta->type;
    results.active = fsMeta->flags & TSK_FS_META_FLAG_ALLOC ? 1 : 0;
    if (fsMeta->name2 != NULL) {
      results.name = std::string(fsMeta->name2->name);
    }
  } else {
    return 1;
  }
  char* sid;
  if (0 == tsk_fs_file_get_owner_sid(fsFile, &sid)) {
    results.sid = std::string(sid);
    delete sid;
  }
  processAttrs(fsFile, results);

  if (collect_parent_path) {
    std::stringstream path_str;
    int p_rval = collectPath(results.filename.parent.inode, path_str);
    if (p_rval == 0) {
      results.parent_path = path_str.str();
      path_str << "/" << results.name;
      results.path = path_str.str();
    }
  }
  return 0;
}

void Partition::recurseDirectory(void (*callback)(FileInfo&, void*),
                                 void* context,
                                 std::string* path,
                                 TSK_FS_DIR* dir,
                                 TSK_INUM_T parent,
                                 int depth,
                                 std::unordered_set<uint64_t>& processed) {
  if (depth <= 0) {
    return;
  }
  TSK_INUM_T current_inode = dir->addr;
  processed.insert(current_inode);

  for (int i = 0; i < tsk_fs_dir_getsize(dir); ++i) {
    TSK_FS_FILE* fsFile = tsk_fs_dir_get(dir, i);
    if (fsFile == NULL) {
      continue;
    }

    FileInfo f;
    int rval = getFileInfo(fsFile, f, false);
    tsk_fs_file_close(fsFile);

    // failed to read, got a weird file, or got the current dir again? skip it.
    if (rval != 0 || f.inode == 0 || current_inode == f.inode ||
        parent == f.inode) {
      continue;
    }
    f.parent_path = *path;
    f.path = *path + std::string("/") + f.name;
    if (callback) {
      callback(f, context);
    }
    if (f.type == TSK_FS_META_TYPE_DIR) {
      if (0 == processed.count(f.inode)) {
        TSK_FS_DIR* fsDir = tsk_fs_dir_open_meta(fsInfo, f.inode);
        if (NULL != fsDir) {
          recurseDirectory(callback,
                           context,
                           &f.path,
                           fsDir,
                           current_inode,
                           depth - 1,
                           processed);
          tsk_fs_dir_close(fsDir);
        }
      }
    }
  }
}

void Partition::recurseDirectory(void (*callback)(FileInfo&, void*),
                                 void* context,
                                 std::string* path,
                                 int depth) {
  TSK_FS_DIR* dir = tsk_fs_dir_open(fsInfo, path->c_str());
  if (dir != NULL) {
    FileInfo f;
    TSK_FS_FILE* fsFile = tsk_fs_file_open_meta(fsInfo, NULL, dir->addr);
    if (fsFile == NULL) {
      tsk_fs_dir_close(dir);
      return;
    }
    getFileInfo(fsFile, f, false);
    tsk_fs_file_close(fsFile);
    std::unordered_set<uint64_t> processed;
    recurseDirectory(callback,
                     context,
                     path,
                     dir,
                     f.filename.parent.inode,
                     depth,
                     processed);
    tsk_fs_dir_close(dir);
  }
}

void Partition::walkPartition(void (*callback)(FileInfo&, void*),
                              void* context) {
  TSK_FS_DIR* dir = tsk_fs_dir_open_meta(fsInfo, fsInfo->root_inum);
  if (dir == NULL) {
    return;
  }
  int max_depth = INT32_MAX;
  std::string path("");
  std::unordered_set<uint64_t> processed;
  recurseDirectory(
      callback, context, &path, dir, UINT64_MAX, max_depth, processed);
  tsk_fs_dir_close(dir);
}

void Partition::collectINDX(std::string& path,
                            trailofbits::DirEntryList& entries) {
  TSK_FS_FILE* fsFile = tsk_fs_file_open(fsInfo, NULL, path.c_str());
  if (fsFile == NULL) {
    std::cerr << "unable to open file " << path << "\n";
    return;
  }

  collectINDX(fsFile, entries);
  tsk_fs_file_close(fsFile);
}

void Partition::collectINDX(uint64_t inode,
                            trailofbits::DirEntryList& entries) {
  TSK_FS_FILE* fsFile = tsk_fs_file_open_meta(fsInfo, NULL, inode);
  if (fsFile == NULL) {
    std::cerr << "unable to open file with inode " << inode << "\n";
    return;
  }

  collectINDX(fsFile, entries);
  tsk_fs_file_close(fsFile);
}

bool processDirectoryIndexEntry(
    const uint8_t* data,
    trailofbits::ntfs_directory_index_entry_t& entry,
    size_t size) {
  //  0 -  7	MFT file reference
  //  8 -  9	length of this entry
  // 10 - 11	length of file_name attribute
  // 12 - 15	flags
  // 16+		file name
  // Last 8 bytes, aligned: if flag is set, VCN of child node
  processFileReference(data, entry.mft_ref);
  uintFromBuffer(data, 8, entry.entry_length);
  uintFromBuffer(data, 10, entry.name_length);
  uintFromBuffer(data, 12, entry.flags);

  if (entry.entry_length > size || (entry.name_length + 16) > size) {
    return false;
  }

  if (entry.name_length != 0) {
    processFileNameBuffer(data + 16, entry.filename, entry.name_length);
  }

  if (entry.flags & 0x1) {
    uintFromBuffer(data,
                   entry.entry_length - 8 - ((entry.entry_length - 8) % 8),
                   entry.child_vcn);
  }
  return true;
}

void processDirIndexNodesAndEntries(const uint8_t* data,
                                    size_t size,
                                    DirEntryList& entries) {
  //  0 -  3	offset to start of index entry list (relative to start of node
  //  header)
  //  4 -  7	offset to end of used portion of index entry list (relative to
  //  start of node header)
  //  8 - 11	offset to end of allocated index enty list buffer (relative to
  //  start of node header)
  // 12 - 15	Flags
  uint32_t starting_offset, alloc_offset, used_offset;
  uintFromBuffer(data, 0, starting_offset);
  uintFromBuffer(data, 4, used_offset);
  uintFromBuffer(data, 8, alloc_offset);

  uint32_t offset = starting_offset;
  while (offset < used_offset) {
    trailofbits::ntfs_directory_index_entry entry;
    processDirectoryIndexEntry(data + offset, entry, size - offset);
    if (entry.name_length > 0) {
      entries.push_back(entry);
    }
    offset += entry.entry_length;

    if (entry.flags & 0x2) {
      // last entry in list
      break;
    }
  }

  while (offset < size && offset < (size - 0x52)) {
    trailofbits::ntfs_directory_index_entry entry;
    bool rval = processDirectoryIndexEntry(data + offset, entry, size - offset);
    entry.slack_addr = offset;
    if (rval && entry.valid()) {
      entries.push_back(entry);
    } else {
      offset += 1;
      continue;
    }
    offset += entry.entry_length;
  }
}

void processDirectoryIndexAttribute(const TSK_FS_ATTR* attrib,
                                    DirEntryList& entries,
                                    uint32_t& record_size) {
  // index record header:
  // 0 - 3 signature
  // 4 - 5 offset to fixup array
  // 6 - 7 number of entries in fixup array
  // 8 - 15 LSN
  // 16 - 23 VCN
  // node header
  // fixup array
  // index entries[]

  uint64_t vcn;
  uint32_t offset = 0;
  uint16_t fixup_offset, fixup_count, fixup_signature, fixup_entry;

  char* buffer = new char[record_size];

  while (offset + record_size <= attrib->size) {
    ssize_t bytes_read = tsk_fs_attr_read(
        attrib, offset, buffer, record_size, TSK_FS_FILE_READ_FLAG_NONE);
    if (bytes_read < record_size) {
      std::cerr << "read " << bytes_read << " of requested " << record_size
                << " bytes\n";
      return; // abort?
    }
    uint8_t* ptr = (uint8_t*)buffer;

    // apply fixup
    uintFromBuffer(ptr, 4, fixup_offset);
    uintFromBuffer(ptr, 6, fixup_count);
    uintFromBuffer(ptr, fixup_offset, fixup_signature);
    for (unsigned int i = 1; i < fixup_count && (i * 512) < record_size; ++i) {
      uint16_t sector_bytes;
      uintFromBuffer(ptr, fixup_offset + (2 * i), fixup_entry);
      uintFromBuffer(ptr, (i * 512) - 2, sector_bytes);
      if (sector_bytes == fixup_signature) {
        memcpy(ptr + (i * 512) - 2, ptr + fixup_offset + (2 * i), 2);
      }
    }

    uintFromBuffer(ptr, 16, vcn);
    processDirIndexNodesAndEntries(ptr + 24, record_size - 24, entries);
    offset += record_size;
  }
  delete[] buffer;
}

void processDirectoryIndexRootAttrib(const TSK_FS_ATTR* attrib,
                                     DirEntryList& entries,
                                     uint32_t& record_size) {
  //  Index Root Header Index Node Header Index Entries[]
  // |-----------------|-----------------|-------------|--------
  //  0 -  3	attribute type
  //  4 -  7	collation sorting rule
  //  8 - 11	size of each index record in bytes
  // 12 - 12	size of each index record in clusters
  // 13 - 15	unused
  // 16+		node header
  uint32_t attrib_type;

  const uint8_t* data = attrib->rd.buf;
  uintFromBuffer(data, 0, attrib_type);
  if (attrib_type != 48) {
    std::cerr << "processDirectoryIndexRootAttrib called on index root that "
                 "doesn't index file_name\n";
    return;
  }
  uintFromBuffer(data, 8, record_size);
  processDirIndexNodesAndEntries(data + 16, attrib->size - 16, entries);
}

void Partition::collectINDX(TSK_FS_FILE* fsFile, DirEntryList& entries) {
  uint32_t record_size = 0;
  for (int i = 0; i < tsk_fs_file_attr_getsize(fsFile); ++i) {
    const TSK_FS_ATTR* attrib = tsk_fs_file_attr_get_idx(fsFile, i);
    if (attrib == NULL) {
      continue;
    }
    switch (attrib->type) {
    case 144: // IDXROOT
      processDirectoryIndexRootAttrib(attrib, entries, record_size);
      break;
    case 160: // IDXALLOC
      if (record_size != 0) {
        processDirectoryIndexAttribute(attrib, entries, record_size);
      } else {
        std::cerr << "record_size is 0, skipping IDXALLOC attribute\n";
      }
      break;
    }
  }
}
}
