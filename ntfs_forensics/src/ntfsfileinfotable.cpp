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
  osquery::QueryData& result;
  const std::string& dev;
  int partition;
  const std::string* from_cache;
};

void populateRow(osquery::Row& r,
                 NTFSFileInformation& info,
                 const std::string& dev,
                 int partition,
                 const std::string* from_cache = NULL) {
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

  if (from_cache != NULL) {
    r["from_cache"] = *from_cache;
  }
}

void callback(NTFSFileInformation& info, void* context) {
  query_context_t* qct = static_cast<query_context_t*>(context);

  osquery::Row r;
  populateRow(r, info, qct->dev, qct->partition, qct->from_cache);
  qct->result.push_back(r);
}

osquery::QueryData NTFSFileInfoTablePlugin::generate(
    osquery::QueryContext& request) {
  osquery::QueryData result;

  auto devices = request.constraints["device"].getAll(osquery::EQUALS);
  auto partitions = request.constraints["partition"].getAll(osquery::EQUALS);

  auto paths = request.constraints["path"].getAll(osquery::EQUALS);
  auto inodes = request.constraints["inode"].getAll(osquery::EQUALS);
  auto directories = request.constraints["directory"].getAll(osquery::EQUALS);
  auto from_cache = request.constraints["from_cache"].getAll(osquery::EQUALS);

  const std::string* from_cache_val = NULL;

  bool clear_cache = false;
  if (from_cache.size() == 1) {
    int cache_val = 1;
    std::stringstream cache_str;
    cache_str << *(from_cache.begin());
    cache_str >> cache_val;
    clear_cache = (cache_val == 0);
    from_cache_val = &(*(from_cache.begin()));
  }

  if (devices.empty() || partitions.size() != 1) {
    return {};
  }

  std::stringstream part_stream;
  int partition;
  part_stream << *(partitions.begin());
  part_stream >> partition;

  for (const auto& dev : devices) {
    DiskDevice* d = NULL;
    DiskPartition* p = NULL;
    try {
      d = new DiskDevice(dev);
      p = new DiskPartition(*d, partition);
    } catch (std::runtime_error&) {
      delete p;
      delete d;
      continue;
    }

    NTFSFileInformation info;
    int rval = -1;

    if (paths.size() == 1) {
      rval = p->getFileInfo(std::string(*(paths.begin())), info);
    } else if (inodes.size() == 1) {
      std::stringstream inode_str;
      uint64_t inode;
      inode_str << *(inodes.begin());
      inode_str >> inode;
      rval = p->getFileInfo(inode, info);
    } else if (directories.size() == 1) {
      query_context_t context = {result, dev, partition, NULL};
      std::string dir(*(directories.begin()));
      p->recurseDirectory(callback, &context, &dir, 1);
      rval = 1;
    } else {
      std::stringstream map_key;
      map_key << dev << "," << partition;
      auto it = cache.find(map_key.str());
      if (clear_cache && it != cache.end()) {
        cache.erase(it);
        it = cache.end();
      }
      if (it != cache.end()) {
        result = it->second;
      } else {
        query_context_t context = {result, dev, partition, from_cache_val};
        p->walkPartition(callback, &context);
        rval = 1;
        cache[map_key.str()] = result;
      }
    }
    if (rval == 0) {
      osquery::Row r;
      populateRow(r, info, dev, partition);

      result.push_back(r);
    }

    delete p;
    delete d;
  }
  return result;
}
}
