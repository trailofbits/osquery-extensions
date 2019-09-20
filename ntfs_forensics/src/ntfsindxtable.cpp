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
#include "ntfsdirectoryindexentry.h"
#include "ntfsindxtable.h"

namespace trailofbits {
namespace {
void populateIndexRow(osquery::Row& r,
                      NTFSDirectoryIndexEntry& entry,
                      const std::string& dev,
                      int partition,
                      const std::string& parent_path) {
  r["device"] = dev;
  r["partition"] = std::to_string(partition);

  r["parent_inode"] = std::to_string(entry.filename.parent.inode);
  r["parent_path"] = parent_path;

  r["filename"] = entry.filename.filename;
  r["inode"] = std::to_string(entry.mft_ref.inode);

  r["allocated_size"] = std::to_string(entry.filename.allocated_size);
  r["real_size"] = std::to_string(entry.filename.real_size);

  r["flags"] = std::to_string(entry.filename.flags);

  r["btime"] = std::to_string(entry.filename.file_name_times.btime);
  r["mtime"] = std::to_string(entry.filename.file_name_times.mtime);
  r["ctime"] = std::to_string(entry.filename.file_name_times.ctime);
  r["atime"] = std::to_string(entry.filename.file_name_times.atime);

  r["slack"] = std::to_string(entry.slack_addr);
}

void generateAndAppendRows(
    osquery::TableRows& results,
    const std::unordered_set<std::uint64_t>& inode_constraints,
    std::shared_ptr<DiskPartition> partition,
    const std::string& device_name,
    std::uint32_t partition_number) {
  for (const auto& inode : inode_constraints) {
    DirEntryList entries = {};
    NTFSFileInformation fileInfo = {};

    partition->collectINDX(inode, entries);
    partition->getFileInfo(inode, fileInfo);

    for (auto& entry : entries) {
      osquery::Row r = {};
      populateIndexRow(r, entry, device_name, partition_number, fileInfo.path);

      results.push_back(std::move(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r)))));
    }
  }
}

void generateAndAppendRows(osquery::TableRows& results,
                           const std::set<std::string>& path_constraints,
                           std::shared_ptr<DiskPartition> partition,
                           const std::string& device_name,
                           std::uint32_t partition_number) {
  for (const auto& path : path_constraints) {
    DirEntryList entries = {};
    NTFSFileInformation fileInfo = {};

    // Fix up the root path specifier
    if (path == "/") {
      partition->collectINDX("/.", entries);
      partition->getFileInfo("/.", fileInfo);
      fileInfo.path = path;
    } else {
      partition->collectINDX(path, entries);
      partition->getFileInfo(path, fileInfo);
    }

    for (auto& entry : entries) {
      osquery::Row r = {};
      populateIndexRow(r, entry, device_name, partition_number, fileInfo.path);

      results.push_back(std::move(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r)))));
    }
  }
}
}

osquery::TableColumns NTFSINDXTablePugin::columns() const {
  // clang-format off
  return {
    std::make_tuple("device", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("partition", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("parent_inode", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("parent_path", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("inode", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("allocated_size", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("real_size", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("btime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("mtime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("ctime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("atime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("flags", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("slack", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::TableRows NTFSINDXTablePugin::generate(
    osquery::QueryContext& request) {
  // Get the statement constraints
  auto path_constraints =
      request.constraints["parent_path"].getAll(osquery::EQUALS);

  std::unordered_set<std::uint64_t> inode_constraints;
  auto status =
      getParentInodeConstraints(inode_constraints, request, "parent_inode");
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return {};
  }

  // Build the disk device map according to the constraints we have been given
  DiskDeviceMap device_constraints;
  status = getDeviceAndPartitionConstraints(device_constraints, request);
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return {};
  }

  if (path_constraints.empty() == inode_constraints.empty()) {
    LOG(WARNING) << "Invalid or missing constraints; either parent_path or "
                    "parent_inode is required";
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
        //error code 2 is explicitly the code for unable to open filesystem
        //this is common if partition is not specified and there are
        //multiple non-NTFS partitions
        if (status.getCode() != 2) {
          LOG(WARNING) << status.getMessage();
        }
        continue;
      }

      // Use the constraint the user has selected to emit the rows
      if (!inode_constraints.empty()) {
        generateAndAppendRows(results,
                              inode_constraints,
                              disk_partition,
                              device_name,
                              partition_number);
      } else {
        generateAndAppendRows(results,
                              path_constraints,
                              disk_partition,
                              device_name,
                              partition_number);
      }
    }
  }

  return results;
}
}
