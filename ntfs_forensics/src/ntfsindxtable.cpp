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

#include "ntfs_forensics.h"
#include "ntfsindxtable.h"

namespace trailofbits {
osquery::TableColumns NTFSINDXTablePugin::columns() const {
  return {
      std::make_tuple(
          "device", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "partition", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "parent_inode", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "parent_path", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "inode", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple("allocated_size",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "real_size", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "btime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "mtime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "ctime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "atime", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "flags", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

      std::make_tuple(
          "slack", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

  };
}

void populateIndexRow(osquery::Row& r,
                      trailofbits::ntfs_directory_index_entry_t& entry,
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

osquery::QueryData NTFSINDXTablePugin::generate(
    osquery::QueryContext& request) {
  osquery::QueryData results;

  auto devices = request.constraints["device"].getAll(osquery::EQUALS);
  auto partitions = request.constraints["partition"].getAll(osquery::EQUALS);

  auto paths = request.constraints["parent_path"].getAll(osquery::EQUALS);
  auto inodes = request.constraints["parent_inode"].getAll(osquery::EQUALS);

  if (devices.empty() || partitions.size() != 1) {
    return {};
  }

  std::stringstream part_stream;
  int partition;
  part_stream << *(partitions.begin());
  part_stream >> partition;

  for (const auto& dev : devices) {
    trailofbits::Device* d = NULL;
    trailofbits::Partition* p = NULL;
    try {
      d = new trailofbits::Device(dev);
      p = new trailofbits::Partition(*d, partition);
    } catch (std::runtime_error&) {
      delete p;
      delete d;
      continue;
    }

    trailofbits::DirEntryList entries;
    trailofbits::FileInfo fileInfo;
    if (paths.size() == 1) {
      p->collectINDX(std::string(*(paths.begin())), entries);
      p->getFileInfo(*(paths.begin()), fileInfo);
    } else if (inodes.size() == 1) {
      std::stringstream inode_str;
      uint64_t inode;
      inode_str << *inodes.begin();
      inode_str >> inode;
      p->collectINDX(inode, entries);
      p->getFileInfo(inode, fileInfo);
    }

    for (auto& entry : entries) {
      osquery::Row r;
      populateIndexRow(r, entry, dev, partition, fileInfo.path);
      results.push_back(r);
    }
    delete p;
    delete d;
  }
  return results;
}
}