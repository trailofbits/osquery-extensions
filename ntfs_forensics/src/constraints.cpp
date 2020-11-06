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

#pragma once

#include "constraints.h"

#include <cstdint>
#include <string>
#include <unordered_set>

#include <osquery/logger/logger.h>

#include "diskpartition.h"

namespace trailofbits {
osquery::Status getParentInodeConstraints(
    std::unordered_set<std::uint64_t>& inode_constraints,
    const osquery::QueryContext& request,
    const std::string& key_name) {
  inode_constraints.clear();

  auto constraint_it = request.constraints.find(key_name);
  if (constraint_it == request.constraints.end()) {
    return osquery::Status(0);
  }

  const auto& constraint_set = constraint_it->second;
  auto str_inode_constraints = constraint_set.getAll(osquery::EQUALS);

  bool conversion_error = false;

  for (const auto& inode_str : str_inode_constraints) {
    char* null_term_ptr = nullptr;
    auto inode = std::strtoull(inode_str.c_str(), &null_term_ptr, 10);
    if (*null_term_ptr != 0) {
      conversion_error = true;

      VLOG(1) << "Invalid inode constraint specified: " << inode
              << ". Skipping...";

      continue;
    }

    inode_constraints.insert(inode);
  }

  if (conversion_error && inode_constraints.empty()) {
    return osquery::Status(1, "Failed to parse the inode constraints");
  }

  return osquery::Status(0);
}

osquery::Status getDeviceAndPartitionConstraints(
    DiskDeviceMap& device_map, const osquery::QueryContext& request) {
  device_map.clear();

  // Get the device constraints
  std::set<std::string> device_constraints;

  auto constraint_it = request.constraints.find("device");
  if (constraint_it != request.constraints.end()) {
    const auto& constraint_set = constraint_it->second;
    device_constraints = constraint_set.getAll(osquery::EQUALS);
  }

  // Get the partition constraints
  std::set<std::uint32_t> partition_constraints;

  constraint_it = request.constraints.find("partition");
  if (constraint_it != request.constraints.end()) {
    const auto& constraint_set = constraint_it->second;
    auto str_partition_constraints = constraint_set.getAll(osquery::EQUALS);

    bool conversion_error = false;
    for (const auto& partition_str : str_partition_constraints) {
      char* null_term_ptr = nullptr;
      auto partition_number =
          std::strtoul(partition_str.c_str(), &null_term_ptr, 10);

      if (*null_term_ptr != 0) {
        conversion_error = true;
        VLOG(1) << "Invalid partition specified: " << partition_str
                << ". Skipping...";

        continue;
      }

      partition_constraints.insert(
          static_cast<std::uint32_t>(partition_number));
    }

    if (conversion_error && partition_constraints.empty()) {
      return osquery::Status(1, "Invalid partition constraints specified");
    }
  }

  // Build the device map, skipping anything that does not match our
  // constraints (if any)
  for (const auto& current_partition : getPartitionList()) {
    if (!device_constraints.empty() &&
        device_constraints.count(current_partition.device) == 0) {
      continue;
    }

    if (!partition_constraints.empty() &&
        partition_constraints.count(current_partition.part_address) == 0) {
      continue;
    }

    auto device_it = device_map.find(current_partition.device);
    if (device_it == device_map.end()) {
      device_map.insert(
          {current_partition.device, {current_partition.part_address}});

    } else {
      auto& partition_set = device_it->second;
      partition_set.insert(current_partition.part_address);
    }
  }

  return osquery::Status(0);
}
} // namespace trailofbits
