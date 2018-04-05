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

  if (devices.empty() || partitions.size() != 1 || paths.size() != 1) {
	  return {};
  }

  std::stringstream part_stream;
  int partition;
  part_stream << *partitions.begin();
  part_stream >> partition;
  const std::string path = *paths.begin();

  for (const auto& dev : devices) {
	  FileInfo info;
	  getFileInfo(dev, partition, path, info);
	  osquery::Row r;
	  r["device"] = dev;
	  r["partition"] = std::to_string(partition);
	  r["path"] = path;

	  r["filenme"] = info.name;

	  r["btime"] = std::to_string(info.standard_info_times.btime);
	  r["mtime"] = std::to_string(info.standard_info_times.mtime);
	  r["ctime"] = std::to_string(info.standard_info_times.ctime);
	  r["atime"] = std::to_string(info.standard_info_times.atime);

	  r["fn_btime"] = std::to_string(info.file_name_times.btime);
	  r["fn_mtime"] = std::to_string(info.file_name_times.mtime);
	  r["fn_ctime"] = std::to_string(info.file_name_times.ctime);
	  r["fn_atime"] = std::to_string(info.file_name_times.atime);

	  r["allocated"] = std::to_string(info.allocated_size);
	  r["size"] = std::to_string(info.real_size);

	  std::stringstream oid;
	  for (int i = 0; i < 16; ++i) {
		  oid << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(info.object_id[i]);
	  }
	  r["object_id"] = oid.str();

	  result.push_back(r);
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