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

FileInfo::FileInfo() {
	memset(this, 0, sizeof(FileInfo));
}

std::string FileInfo::getStringRep() const {
	// for ease of debugging
	std::stringstream output;

	output << "name: \"" << this->name << "\"\n"
		<< "path: \"" << this->path << "\"\n"
		<< "parent: " << this->parent.inode << "," << this->parent.sequence << "\n"
		<< "btime:    " << this->standard_info_times.btime << "\n"
		<< "mtime:    " << this->standard_info_times.mtime << "\n"
		<< "ctime:    " << this->standard_info_times.ctime << "\n"
		<< "atime:    " << this->standard_info_times.atime << "\n"
		<< "fn_btime: " << this->file_name_times.btime << "\n"
		<< "fn_mtime: " << this->file_name_times.mtime << "\n"
		<< "fn_ctime: " << this->file_name_times.ctime << "\n"
		<< "fn_atime: " << this->file_name_times.atime << "\n"
		<< "type: " << typeNameFromInt(this->type) << "\n"
		<< "active: " << (this->active > 0 ? "true" : "false") << "\n";
	std::stringstream flags, fn_flags;
	flags << "0x" << std::hex << std::setfill('0') << std::setw(8) << this->flag_val << "\n";
	fn_flags << "0x" << std::hex << std::setfill('0') << std::setw(8) << this->fn_flag_val << "\n";
	output << "flags: " << flags.str()
		<< "fn_flags: " << fn_flags.str()

		<< "ads: " << (this->ads == 0 ? "false" : "true") << "\n"
		<< "allocated: " << this->allocated_size << "\n"
		<< "size:      " << this->real_size << "\n"
		<< "inode: " << this->inode << "\n"
		<< "uid: " << this->uid << "\n"
		<< "gid: " << this->gid << "\n";

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

void processFlags(uint32_t f, flags_t &flags) {
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

void processParentReference(const uint8_t *data, ntfs_parent_t& parent) {
	parent.inode = 0;
	parent.sequence = 0;
	uint64_t raw_val = *(reinterpret_cast<const uint64_t*>(data));
	parent.inode = raw_val & 0xFFFFFFFFFFFF;
	parent.sequence = (raw_val >> 32) & 0xFFFF;
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
	if (attrib->getSize() >= 60) {
		const uint8_t* data = attrib->getBuf();
		processParentReference(data, results.parent);
		uintFromBuffer(data, 8, results.file_name_times.btime);
		uintFromBuffer(data, 16, results.file_name_times.mtime);
		uintFromBuffer(data, 24, results.file_name_times.ctime);
		uintFromBuffer(data, 32, results.file_name_times.atime);
		uintFromBuffer(data, 40, results.allocated_size);
		uintFromBuffer(data, 48, results.real_size);
		results.fn_flag_val = *(reinterpret_cast<const uint32_t*>(&data[56]));
	}
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
	if (attrib->getSize() >= 36) {
		const uint8_t* data = attrib->getBuf();
		uintFromBuffer(data, 0, results.standard_info_times.btime);
		uintFromBuffer(data, 8, results.standard_info_times.mtime);
		uintFromBuffer(data, 16, results.standard_info_times.ctime);
		uintFromBuffer(data, 24, results.standard_info_times.atime);
		results.flag_val = *(reinterpret_cast<const uint32_t*>(&data[32]));
		processFlags(results.flag_val, results.flags);
	}
}

void processAttrs(TskFsFile* fsFile, FileInfo &results) {
	int dataAttribCount = 0;
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
				break;
			case 128:
				// data attribute, track for ADS
				++dataAttribCount;
				break;
			}
		}
		delete attrib;
	}
	results.ads = (dataAttribCount > 1 ? 1 : 0);
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

Device::Device(const std::string& device) {
	int rval = imgInfo.open(device.c_str(), TSK_IMG_TYPE_DETECT, 0);
	if (rval != 0) { throw std::runtime_error("unable to open device"); }
}

Partition::Partition(Device& device, int partition_index) : vsPartInfo(NULL) {
	int rval = volInfo.open(&device.imgInfo, 0, TSK_VS_TYPE_DETECT);
	if (rval != 0) { throw std::runtime_error("unable to open volume"); }

	vsPartInfo = volInfo.getPart(partition_index);
	if (vsPartInfo == NULL) { throw std::runtime_error("unable to open partition"); }

	rval = fsInfo.open(vsPartInfo, TSK_FS_TYPE_DETECT);
	if (rval != 0) {
		throw std::runtime_error("unable to open filesystem");
	}
}

Partition::~Partition() {
	fsInfo.close();
	delete vsPartInfo;
}

int Partition::getFileInfo(const std::string& path, FileInfo &results) {
	int rval = 0;

	TskFsFile fsFile;
	rval = fsFile.open(&fsInfo, &fsFile, path.c_str());
	if (rval != 0) {
		return 6;
	}
	rval = getFileInfo(fsFile, results);
	fsFile.close();
	return rval;
}

int Partition::getFileInfo(uint64_t inode, FileInfo &results) {
	int rval = 0;
	TskFsFile fsFile;
	rval = fsFile.open(&fsInfo, &fsFile, inode);
	if (rval != 0) {
		return 6;
	}
	rval = getFileInfo(fsFile, results);
	fsFile.close();
	return rval;
}

int Partition::getFileInfo(TskFsFile& fsFile, FileInfo &results) {
	int rval = 0;
	TskFsMeta* fsMeta = fsFile.getMeta();
	if (fsMeta != NULL) {
		results.inode = fsMeta->getAddr();
		results.gid = fsMeta->getGid();
		results.uid = fsMeta->getUid();
		results.type = fsMeta->getType();
		results.active = fsMeta->getFlags() & TSK_FS_META_FLAG_ALLOC ?  1 : 0;
		if (fsMeta->getName2Count() > 0) {
			results.name = std::string(fsMeta->getName2(0)->getName());
		}
	}
	delete fsMeta;

	processAttrs(&fsFile, results);


	return rval;
}
