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
    osquery::QueryData& results,
    const std::unordered_set<std::uint64_t>& inode_constraints,
    DiskPartition& partition,
    const std::string& device_name,
    std::uint32_t partition_number) {
  for (const auto& inode : inode_constraints) {
    DirEntryList entries = {};
    NTFSFileInformation fileInfo = {};

    partition.collectINDX(inode, entries);
    partition.getFileInfo(inode, fileInfo);

    for (auto& entry : entries) {
      osquery::Row r = {};
      populateIndexRow(r, entry, device_name, partition_number, fileInfo.path);

      results.push_back(std::move(r));
    }
  }
}

void generateAndAppendRows(osquery::QueryData& results,
                           const std::set<std::string>& path_constraints,
                           DiskPartition& partition,
                           const std::string& device_name,
                           std::uint32_t partition_number) {
  for (const auto& path : path_constraints) {
    DirEntryList entries = {};
    NTFSFileInformation fileInfo = {};

    // The root folder is a special case; we have to query it by inode
    if (path == "/") {
      NTFSFileInformation root_file_info;
      partition.getFileInfo(path, root_file_info);

      partition.collectINDX(root_file_info.inode, entries);
      partition.getFileInfo(root_file_info.inode, fileInfo);

    } else {
      partition.collectINDX(path, entries);
      partition.getFileInfo(path, fileInfo);
    }

    for (auto& entry : entries) {
      osquery::Row r = {};
      populateIndexRow(r, entry, device_name, partition_number, fileInfo.path);

      results.push_back(std::move(r));
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

osquery::QueryData NTFSINDXTablePugin::generate(
    osquery::QueryContext& request) {
  // Make sure we have at least one (valid) constraint specified
  auto path_constraints =
      request.constraints["parent_path"].getAll(osquery::EQUALS);

  auto str_inode_constraints =
      request.constraints["parent_inode"].getAll(osquery::EQUALS);

  std::unordered_set<std::uint64_t> inode_constraints;
  for (const auto& inode_str : str_inode_constraints) {
    char* null_term_ptr = nullptr;
    auto inode = std::strtoull(inode_str.c_str(), &null_term_ptr, 10);
    if (*null_term_ptr != 0) {
      VLOG(1) << "Invalid inode constraint specified: " << inode
              << ". Skipping...";

      continue;
    }

    inode_constraints.insert(inode);
  }

  if (path_constraints.empty() == inode_constraints.empty()) {
    LOG(WARNING) << "Invalid or missing constraints; either parent_path or "
                    "parent_inode is required.";

    return {{}};
  }

  // Enumerate the devices we have
  std::unordered_map<std::string, std::unordered_set<std::uint32_t>> device_map;

  for (const auto& current_partition : getPartitionList()) {
    auto device_it = device_map.find(current_partition.device);
    if (device_it == device_map.end()) {
      device_map.insert(
          {current_partition.device, {current_partition.part_address}});

    } else {
      auto& partition_set = device_it->second;
      partition_set.insert(current_partition.part_address);
    }
  }

  // Get the SQL statement constraints
  auto device_constraints =
      request.constraints["device"].getAll(osquery::EQUALS);

  if (device_constraints.empty()) {
    for (const auto& p : device_map) {
      const auto& device_name = p.first;
      device_constraints.insert(device_name);
    }
  }

  std::unordered_set<std::uint32_t> partition_constraints;
  for (const auto& partition_str :
       request.constraints["partition"].getAll(osquery::EQUALS)) {
    char* null_term_ptr = nullptr;
    auto partition_number =
        std::strtoul(partition_str.c_str(), &null_term_ptr, 10);

    if (*null_term_ptr != 0) {
      VLOG(1) << "Invalid partition specified: " << partition_str
              << ". Skipping...";

      continue;
    }

    partition_constraints.insert(static_cast<std::uint32_t>(partition_number));
  }

  // Iterate through all devices
  osquery::QueryData results;

  for (const auto& device_name : device_constraints) {
    // Make sure the specified device exists
    auto device_map_it = device_map.find(device_name);
    if (device_map_it == device_map.end()) {
      VLOG(1) << "Device " << device_name << " was not found. Skipping...";
      continue;
    }

    const auto& available_device_partitions = device_map_it->second;

    // Iterate through all partitions
    std::unordered_set<std::uint32_t> partition_list;
    if (partition_constraints.empty()) {
      partition_list = available_device_partitions;
    }

    for (const auto& partition_number : partition_list) {
      DiskDevice* d = nullptr;
      DiskPartition* p = nullptr;
      try {
        d = new DiskDevice(device_name);
        p = new DiskPartition(*d, partition_number);
      } catch (std::runtime_error&) {
        delete p;
        delete d;
        continue;
      }

      // Use the constraint the user has selected to emit the rows
      if (!inode_constraints.empty()) {
        generateAndAppendRows(
            results, inode_constraints, *p, device_name, partition_number);
      } else {
        generateAndAppendRows(
            results, path_constraints, *p, device_name, partition_number);
      }

      delete p;
      delete d;
    }
  }

  return results;
}
}