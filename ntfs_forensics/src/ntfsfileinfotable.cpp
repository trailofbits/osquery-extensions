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

#include <osquery/tables.h>
#include <osquery/sql/dynamic_table_row.h>

#include "constraints.h"
#include "diskdevice.h"
#include "diskpartition.h"
#include "ntfsfileinformation.h"
#include "ntfsfileinfotable.h"

namespace trailofbits {
osquery::TableColumns NTFSFileInfoTablePlugin::columns() const {
  // clang-format off
  return {
    std::make_tuple("device", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("partition", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("path", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("directory", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("btime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("mtime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("ctime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("atime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("fn_btime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("fn_mtime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("fn_ctime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("fn_atime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("type", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("active", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("flags", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("ADS", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("allocated", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("size", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("inode", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("object_id", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("uid", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("gid", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("sid", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("from_cache", osquery::TEXT_TYPE, osquery::ColumnOptions::HIDDEN)
  };
  // clang-format on
}

struct query_context_t final {
  osquery::TableRows& result;
  const std::string& dev;
  std::uint32_t partition;
};

void populateRow(osquery::Row& r,
                 NTFSFileInformation& info,
                 const std::string& dev,
                 int partition) {
  r["device"] = dev;
  r["partition"] = std::to_string(partition);
  r["path"] = info.path;

  r["filename"] = info.name;

  r["btime"] = std::to_string(info.standard_info_times.btime);
  r["mtime"] = std::to_string(info.standard_info_times.mtime);
  r["ctime"] = std::to_string(info.standard_info_times.ctime);
  r["atime"] = std::to_string(info.standard_info_times.atime);

  r["fn_btime"] = std::to_string(info.filename.file_name_times.btime);
  r["fn_mtime"] = std::to_string(info.filename.file_name_times.mtime);
  r["fn_ctime"] = std::to_string(info.filename.file_name_times.ctime);
  r["fn_atime"] = std::to_string(info.filename.file_name_times.atime);

  r["type"] = typeNameFromInt(info.type);
  r["active"] = info.active > 0 ? "1" : "0";

  r["ADS"] = std::string(info.ads != 0 ? "1" : "0");

  r["inode"] = std::to_string(info.inode);

  r["allocated"] = std::to_string(info.filename.allocated_size);
  r["size"] = std::to_string(info.filename.real_size);

  r["flags"] = std::to_string(info.flag_val);

  r["directory"] = info.parent_path;

  r["uid"] = std::to_string(info.uid);
  r["sid"] = info.sid;

  std::stringstream oid;
  for (int i = 0; i < 16; ++i) {
    oid << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(info.object_id[i]);
  }
  r["object_id"] = oid.str();
}

void callback(NTFSFileInformation& info, void* context) {
  query_context_t* qct = static_cast<query_context_t*>(context);

  osquery::Row r;
  populateRow(r, info, qct->dev, qct->partition);
  qct->result.push_back(r);
}

osquery::TableRows NTFSFileInfoTablePlugin::generate(
    osquery::QueryContext& request) {
  // Get the statement constraints
  auto path_constraints = request.constraints["path"].getAll(osquery::EQUALS);
  auto directory_constraints =
      request.constraints["directory"].getAll(osquery::EQUALS);

  std::unordered_set<std::uint64_t> inode_constraints;
  auto status = getParentInodeConstraints(inode_constraints, request, "inode");
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return {};
  }

  auto constraint_count = 0U;
  if (!path_constraints.empty()) {
    constraint_count++;
  }

  if (!directory_constraints.empty()) {
    constraint_count++;
  }

  if (!inode_constraints.empty()) {
    constraint_count++;
  }

  if (constraint_count != 1U) {
    LOG(WARNING) << "One of the following constraints must be "
                    "specified: path, directory, inode";
    return {};
  }

  // Build the disk device map according to the constraints we have been given
  DiskDeviceMap device_constraints;
  status = getDeviceAndPartitionConstraints(device_constraints, request);
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return {};
  }

  // Iterate through all devices
  osquery::TableRows results;

  for (const auto& p : device_constraints) {
    const auto& device_name = p.first;
    const auto& device_partitions = p.second;

    // Iterate through all partitions
    for (const auto& partition_number : device_partitions) {
      DiskDeviceRef disk_device;
      status = DiskDevice::create(disk_device, device_name);
      if (!status.ok()) {
        LOG(WARNING) << status.getMessage();
        continue;
      }

      DiskPartitionRef disk_partition;
      status =
          DiskPartition::create(disk_partition, disk_device, partition_number);

      if (!status.ok()) {
        // error code 2 is explicitly the code for unable to open filesystem
        // this is common if partition is not specified and there are
        // multiple non-NTFS partitions
        if (status.getCode() != 2) {
          LOG(WARNING) << status.getMessage();
        }
        continue;
      }

      if (!path_constraints.empty()) {
        for (const auto& path : path_constraints) {
          NTFSFileInformation info = {};

          // special case handling for the root dir
          if ("/" == path) {
            auto err = disk_partition->getFileInfo("/.", info);
            if (err != 0) {
              continue;
            }
            info.path = path;
          } else {
            auto err = disk_partition->getFileInfo(path, info);
            if (err != 0) {
              continue;
            }
          }

          osquery::Row r;
          populateRow(r, info, device_name, partition_number);

          results.push_back(std::move(r));
        }

      } else if (!inode_constraints.empty()) {
        for (const auto& inode : inode_constraints) {
          NTFSFileInformation info = {};
          auto err = disk_partition->getFileInfo(inode, info);
          if (err != 0) {
            continue;
          }

          osquery::Row r;
          populateRow(r, info, device_name, partition_number);

          results.push_back(std::move(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r)))));
        }

      } else if (!directory_constraints.empty()) {
        for (const auto& directory : directory_constraints) {
          query_context_t context = {results, device_name, partition_number};
          disk_partition->recurseDirectory(callback, &context, directory, 1);
        }
      }

      // We could work without any constraint, but this is going to have the
      // extension killed by osquery if it takes too long

      /*
        query_context_t context = {results, device_name, partition_number};
        disk_partition->walkPartition(callback, &context);
      */
    }
  }

  return results;
}
}
