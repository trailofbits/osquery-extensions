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

#include <iostream>
#include <iomanip>
#include <sstream>

#include "ntfs_forensics.h"

void processAttrs(TskFsFile* fsFile, FileInfo& result);

std::string FileInfo::getStringRep() const {
	// for ease of debugging
	std::stringstream output;

	output << "name: \"" << this->name << "\"\n"
		<< "path: \"" << this->path << "\"\n"
		<< "directory: \"" << this->directory << "\"\n"
		<< "btime:    " << this->standard_info_times.btime << "\n"
		<< "mtime:    " << this->standard_info_times.mtime << "\n"
		<< "ctime:    " << this->standard_info_times.ctime << "\n"
		<< "atime:    " << this->standard_info_times.atime << "\n"
		<< "fn_btime: " << this->file_name_times.btime << "\n"
		<< "fn_mtime: " << this->file_name_times.mtime << "\n"
		<< "fn_ctime: " << this->file_name_times.ctime << "\n"
		<< "fn_atime: " << this->file_name_times.atime << "\n"
		<< "allocated: " << this->allocated_size << "\n"
		<< "size:      " << this->real_size << "\n";

	std::stringstream oid;
	for (int i = 0; i < 16; ++i) {
		oid << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(this->object_id[i]);
	}

	output << "object_id: " << oid.str() << "\n";
	return output.str();
}

void uintFromBuffer(const uint8_t *data, int64_t offset, uint64_t &result) {
	result = *(reinterpret_cast<const uint64_t*>(&data[offset]));
}

void processFileNameAttrib(const TskFsAttribute* attrib, FileInfo &results) {
	// bytes	description
	//  0 -  7	file reference of parent dir
	//  8 - 15	file creation time
	// 16 - 23	file modification time
	// 24 - 31	MFT modification time
	// 32 - 39	File access time
	// 40 - 47	Allocated size of file
	// 48 - 55	Real size of file
	const uint8_t* data = attrib->getBuf();
	uintFromBuffer(data, 8, results.file_name_times.btime);
	uintFromBuffer(data, 16, results.file_name_times.mtime);
	uintFromBuffer(data, 24, results.file_name_times.ctime);
	uintFromBuffer(data, 32, results.file_name_times.atime);
	uintFromBuffer(data, 40, results.allocated_size);
	uintFromBuffer(data, 48, results.real_size);
}

void processObjectIdAttrib(const TskFsAttribute* attrib, FileInfo& result) {
	// bytes	description
	//  0 - 15	object id
	// 16 - 31	birth volume id
	// 32 - 47	birth object id
	// 48 - 63	birth domain id
	if (attrib->getSize() >= 16) {
		memcpy(result.object_id, attrib->getBuf(), 16);
	}
}

void processStandardAttrib(const TskFsAttribute* attrib, FileInfo &results) {
	// bytes	description
	//  0 -  7	file creation time
	//  8 - 15	file altered time
	// 16 - 23	MFT modification time
	// 24 - 31	File access time
	// 32 - 35	Flags
	const uint8_t* data = attrib->getBuf();
	uintFromBuffer(data, 0, results.standard_info_times.btime);
	uintFromBuffer(data, 8, results.standard_info_times.mtime);
	uintFromBuffer(data, 16, results.standard_info_times.ctime);
	uintFromBuffer(data, 24, results.standard_info_times.atime);
}

void processAttrs(TskFsFile* fsFile, FileInfo &results) {
	for (int i = 0; i < fsFile->getAttrSize(); ++i) {
		const TskFsAttribute* attrib = fsFile->getAttr(i);
		if (attrib != NULL) {
			switch (attrib->getType()) {
			case 48:
				processFileNameAttrib(attrib, results);
				break;
			case 16:
				processStandardAttrib(attrib, results);
				break;
			case 64:
				processObjectIdAttrib(attrib, results);
			}
		}
		delete attrib;
	}
}


/* 
 * Given a specific device, partition on the device, and path to file on the partition,
 * collects infomation about that file from the file system. Returns 0 on success, non-zero
 * on failure.
 */
int getFileInfo(const std::string& device, int partition, std::string path, FileInfo& results) {
	TskImgInfo imgInfo;
	int rval = imgInfo.open(device.c_str(), TSK_IMG_TYPE_DETECT, 0);
	if (rval != 0) { return 1; }
	TskVsInfo volInfo;
	rval = volInfo.open(&imgInfo, 0, TSK_VS_TYPE_DETECT);
	if (rval != 0) { return 2; }

	const TskVsPartInfo *vsPartInfo = volInfo.getPart(partition);
	if (vsPartInfo == NULL) { return 3; }


	TskFsInfo fsInfo;
	rval = fsInfo.open(vsPartInfo, TSK_FS_TYPE_DETECT);
	if (rval != 0) {
		delete vsPartInfo;
		return 4;
	}

	TSK_INUM_T rootDirNum = fsInfo.getRootINum();
	TskFsDir dir;
	rval = dir.open(&fsInfo, rootDirNum);
	if (rval != 0) {
		delete vsPartInfo;
		return 5;
	}

	TskFsFile fsFile;
	rval = fsFile.open(&fsInfo, &fsFile, path.c_str());
	if (rval != 0) {
		delete vsPartInfo;
		return 6;
	}

	TskFsName *name = fsFile.getName();
	if (name != NULL) {
		results.name = std::string(name->getName());
		processAttrs(&fsFile, results);
		rval = 0;
	}
	else { rval = 7; }

	delete name;
	delete vsPartInfo;

	return rval;
}

/* Collects basic info for all partitions for all devices on the system. */
void getPartInfo(PartInfoList& results) {
	results.clear();
	for (unsigned int i = 0; ; ++i) {
		std::stringstream device;
		device << "\\\\.\\PhysicalDrive" << i;
		TskImgInfo imgInfo;
		int rval = imgInfo.open(device.str().c_str(), TSK_IMG_TYPE_DETECT, 0);
		if (rval != 0) { break; } //assuming that all physical drives are contiguously numbered

		TskVsInfo volInfo;
		rval = volInfo.open(&imgInfo, 0, TSK_VS_TYPE_DETECT);
		if (rval != 0) { continue; } // TODO: add support for drives without volumes

		for (unsigned int partIdx = 0; partIdx < volInfo.getPartCount(); ++partIdx) {
			const TskVsPartInfo *vsPartInfo = volInfo.getPart(partIdx);
			if (vsPartInfo != NULL) {
				results.push_back({ device.str(), vsPartInfo->getAddr(), std::string(vsPartInfo->getDesc()) });
			}
			delete vsPartInfo;
		}
	}
}