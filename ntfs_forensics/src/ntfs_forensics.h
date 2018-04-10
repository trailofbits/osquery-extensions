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

#include <string>
#include <list>

#include <tsk/libtsk.h>

typedef struct ntfs_timestamp_struct {
	uint64_t btime;
	uint64_t mtime;
	uint64_t ctime;
	uint64_t atime;
} timestamp_t;

typedef struct ntfs_parent_ref {
	uint64_t inode;
	uint32_t sequence;
} ntfs_parent_t;

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

struct FileInfo {
	std::string name;
	std::string path;
	ntfs_parent_t parent;
	timestamp_t standard_info_times;
	timestamp_t file_name_times;
	int type;
	int active;
	flags_t flags;
	uint32_t flag_val;
	uint32_t fn_flag_val;
	int ads;
	uint64_t allocated_size;
	uint64_t real_size;
	size_t size;
	uint64_t inode;
	uint8_t object_id[16];
	int uid;
	uint32_t gid;

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

std::string typeNameFromInt(int t);

void getPartInfo(PartInfoList& results);

class Partition;

class Device {
public:
	explicit Device(const std::string& dev_name);
private:
	TskImgInfo imgInfo;
	friend class Partition;
};

class Partition {
public:
	explicit Partition(Device &device, int partition_index);
	~Partition();

	int getFileInfo(const std::string& path, FileInfo &results);
	int getFileInfo(uint64_t inode, FileInfo &results);

private:
	int getFileInfo(TskFsFile &file, FileInfo &results);

	TskVsInfo volInfo;
	const TskVsPartInfo* vsPartInfo;
	TskFsInfo fsInfo;
};

int getFileInfo(const std::string& device, int partition, std::string path, FileInfo& results);
int getFileInto(const std::string& device, int partition);