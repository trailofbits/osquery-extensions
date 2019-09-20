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

#include "diskpartition.h"
#include "ntfspartinfotable.h"

namespace trailofbits {
osquery::TableColumns NTFSPartInfoTablePlugin::columns() const {
  // clang-format off
  return {
    std::make_tuple("device", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("address", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("description", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::TableRows NTFSPartInfoTablePlugin::generate(
    osquery::QueryContext& request) {
  static_cast<void>(request);

  osquery::TableRows result;

  for (const auto& part : getPartitionList()) {
    osquery::Row r = {};

    r["device"] = part.device;
    r["address"] = std::to_string(part.part_address);
    r["description"] = part.descriptor;

    result.push_back(std::move(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r)))));
  }

  return result;
}
}
