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

typedef struct timestamp_struct {
	uint64_t btime;
	uint64_t mtime;
	uint64_t ctime;
	uint64_t atime;
} timestamp_t;

struct FileInfo {
	std::string name;
	std::string path;
	std::string directory;
	timestamp_t standard_info_times;
	timestamp_t file_name_times;
	uint64_t allocated_size;
	uint64_t real_size;
	size_t size;
	uint8_t object_id[16];

	std::string getStringRep() const;
};

typedef std::list<FileInfo> FileInfoList;

struct PartInfo {
	std::string device;
	unsigned int part_address;
	std::string descriptor;
};

typedef std::list<PartInfo> PartInfoList;

void getPartInfo(PartInfoList& results);

int getFileInfo(const std::string& device, int partition, std::string path, FileInfo& results);