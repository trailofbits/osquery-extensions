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

#include <osquery/tables.h>

#include "extension.h"
#include "ntfs_forensics.h"

REGISTER_EXTERNAL(NTFSFileInfoTablePlugin, "table", "ntfs_file_data");
REGISTER_EXTERNAL(NTFSPartInfoTablePlugin, "table", "ntfs_part_data");

osquery::TableColumns NTFSFileInfoTablePlugin::columns() const {
  // clang-format off
  return {
	  std::make_tuple("device",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

	  std::make_tuple("partition",
					  osquery::INTEGER_TYPE,
					  osquery::ColumnOptions::DEFAULT),

      std::make_tuple("filename",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("path",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("directory",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("btime",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("mtime",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

	  std::make_tuple("ctime",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

	  std::make_tuple("atime",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

	  std::make_tuple("fn_btime",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

	  std::make_tuple("fn_ctime",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("type",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("active",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("flags",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("ADS",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("allocated",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("size",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("inode",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("object_id",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("uid",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT),

					  std::make_tuple("gid",
					  osquery::TEXT_TYPE,
					  osquery::ColumnOptions::DEFAULT)

  };
  // clang-format on
}

osquery::QueryData NTFSFileInfoTablePlugin::generate(
    osquery::QueryContext& request) {
	osquery::QueryData result;

  auto devices = request.constraints["device"].getAll(osquery::EQUALS);
  auto partitions = request.constraints["partition"].getAll(osquery::EQUALS);

  auto paths = request.constraints["path"].getAll(osquery::EQUALS);
  auto inodes = request.constraints["inode"].getAll(osquery::EQUALS);

  // need a way to identify an entry:
  bool descriminator = (paths.size() == 1 || inodes.size() == 1);

  if (devices.empty() || partitions.size() != 1 || !descriminator) {
	  return {};
  }

  std::stringstream part_stream;
  int partition;
  part_stream << *partitions.begin();
  part_stream >> partition;
  

  for (const auto& dev : devices) {
	  Device *d = NULL;
	  Partition *p = NULL;
	  try {
		  d = new Device(dev);
		  p = new Partition(*d, partition);
	  }
	  catch (std::runtime_error &)
	  {
		  delete p;
		  delete d;
		  continue;
	  }

	  FileInfo info;
	  int rval = -1;

	  if (paths.size() == 1) {
		  rval = p->getFileInfo(std::string(*paths.begin()), info);
	  }
	  else if (inodes.size() == 1) {
		  std::stringstream inode_str;
		  uint64_t inode;
		  inode_str << *inodes.begin();
		  inode_str >> inode;
		  rval = p->getFileInfo(inode, info);
	  }
	  if (rval == 0) {
		  osquery::Row r;
		  r["device"] = dev;
		  r["partition"] = std::to_string(partition);
		  if (paths.size() == 1) {
			  r["path"] = std::string(*paths.begin());
		  }

		  r["filename"] = info.name;

		  r["btime"] = std::to_string(info.standard_info_times.btime);
		  r["mtime"] = std::to_string(info.standard_info_times.mtime);
		  r["ctime"] = std::to_string(info.standard_info_times.ctime);
		  r["atime"] = std::to_string(info.standard_info_times.atime);

		  r["fn_btime"] = std::to_string(info.file_name_times.btime);
		  r["fn_mtime"] = std::to_string(info.file_name_times.mtime);
		  r["fn_ctime"] = std::to_string(info.file_name_times.ctime);
		  r["fn_atime"] = std::to_string(info.file_name_times.atime);

		  r["type"] = typeNameFromInt(info.type);
		  r["active"] = info.active > 0 ? "true" : "false";

		  r["ADS"] = std::string(info.ads == 0 ? "false" : "true");

		  r["inode"] = std::to_string(info.inode);

		  r["allocated"] = std::to_string(info.allocated_size);
		  r["size"] = std::to_string(info.real_size);

		  r["flags"] = std::to_string(info.flag_val);

		  std::stringstream parent;
		  parent << info.parent.inode << "," << info.parent.sequence;
		  r["directory"] = parent.str();

		  std::stringstream oid;
		  for (int i = 0; i < 16; ++i) {
			  oid << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(info.object_id[i]);
		  }
		  r["object_id"] = oid.str();

		  result.push_back(r);
	  }

	  delete p;
	  delete d;
  }
  return result;
}

osquery::TableColumns NTFSPartInfoTablePlugin::columns() const {
	return{
	std::make_tuple("device",
		osquery::TEXT_TYPE,
		osquery::ColumnOptions::DEFAULT),

		std::make_tuple("address",
			osquery::INTEGER_TYPE,
			osquery::ColumnOptions::DEFAULT),

		std::make_tuple("description",
			osquery::TEXT_TYPE,
			osquery::ColumnOptions::DEFAULT)
	};
}

osquery::QueryData NTFSPartInfoTablePlugin::generate(osquery::QueryContext& request) {
	PartInfoList parts;
	getPartInfo(parts);
	osquery::QueryData result;

	for (auto part : parts) {
		osquery::Row r;
		r["device"] = part.device;
		r["address"] = std::to_string(part.part_address);
		r["description"] = part.descriptor;
		result.push_back(r);
	}
	return result;

}