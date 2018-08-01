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

#include <osquery/tables.h>

namespace trailofbits {
/// A disk map, also containing the available partitions for each device
using DiskDeviceMap =
    std::unordered_map<std::string, std::unordered_set<std::uint32_t>>;

/// Returns the inode constraints reading the specified key from the SQL
/// request
osquery::Status getParentInodeConstraints(
    std::unordered_set<std::uint64_t>& inode_constraints,
    const osquery::QueryContext& request,
    const std::string& key_name);

/// Returns a disk device map (device -> partitions) that has been filtered
/// according to the given constraints
osquery::Status getDeviceAndPartitionConstraints(
    DiskDeviceMap& device_map, const osquery::QueryContext& request);
}
