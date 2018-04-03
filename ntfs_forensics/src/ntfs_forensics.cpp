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
#include <sstream>


#include "ntfs_forensics.h"

int getFileInfo(std::string &device, size_t volume_offset, size_t file_offset, FileInfo& results) {
	TskImgInfo imgInfo;
	int rval = imgInfo.open(device.c_str(), TSK_IMG_TYPE_DETECT, 0);
	if (rval != 0) { return 1; }
	TskVsInfo volInfo;
	rval = volInfo.open(&imgInfo, file_offset, TSK_VS_TYPE_DETECT);
	if (rval != 0) { return 2; }

	for (unsigned int i = 0; i < volInfo.getPartCount(); ++i) {
		const TskVsPartInfo *partInfo = volInfo.getPart(i);
		std::cout << "part address: " << partInfo->getAddr() << std::endl;
		std::cout << "part desc: \"" << partInfo->getDesc() << "\"" << std::endl;
	}

	volInfo.close();

	return 0;
}

void printAttrs(TskFsFile* fsFile);


int getFileInfo(const std::string& device,  std::string path, FileInfo& results) {
	TskImgInfo imgInfo;
	int rval = imgInfo.open(device.c_str(), TSK_IMG_TYPE_DETECT, 0);
	if (rval != 0) { return 1; }
	TskVsInfo volInfo;
	rval = volInfo.open(&imgInfo, 0, TSK_VS_TYPE_DETECT);
	if (rval != 0) { return 2; }

	const TskVsPartInfo *vsPartInfo = volInfo.getPart(2);
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
		std::cout << "got the filename, it is \"" << name->getName() << "\"" << std::endl;
		printAttrs(&fsFile);
		rval = 0;
	}
	else { rval = 7; }

	delete name;
	delete vsPartInfo;

	return rval;
}

void printAttrs(TskFsFile* fsFile) {
	for (int i = 0; i < fsFile->getAttrSize(); ++i) {
		const TskFsAttribute* attrib = fsFile->getAttr(i);
		if (attrib != NULL) {
			std::cout << "attrib Id: " << attrib->getId() << std::endl;	
			const char *name = attrib->getName();
			if (name != NULL) {
				std::cout << "attr: \"" << name;
			}
			else {
				std::cout << "attribute with null name" << std::endl;
			}
			std::cout << "flag: " << attrib->getFlags() << std::endl;
			std::cout << "type: " << attrib->getType() << std::endl;
		}
		else {
			std::cout << "null attribute for index " << i << std::endl;
		}
		delete attrib;
	}
}

void getPartInfo(PartInfoList& results) {
	results.clear();
	for (unsigned int i = 0; ; ++i) {
		std::stringstream device;
		device << "\\\\.\\PhysicalDrive" << i;
		TskImgInfo imgInfo;
		int rval = imgInfo.open(device.str().c_str(), TSK_IMG_TYPE_DETECT, 0);
		if (rval != 0) { break; }

		TskVsInfo volInfo;
		rval = volInfo.open(&imgInfo, 0, TSK_VS_TYPE_DETECT);
		if (rval != 0) { continue; } //

		for (unsigned int partIdx = 0; partIdx < volInfo.getPartCount(); ++partIdx) {
			const TskVsPartInfo *vsPartInfo = volInfo.getPart(partIdx);
			if (vsPartInfo != NULL) {
				results.push_back({ device.str(), vsPartInfo->getAddr(), std::string(vsPartInfo->getDesc()) });
			}
			delete vsPartInfo;
		}
	}
}