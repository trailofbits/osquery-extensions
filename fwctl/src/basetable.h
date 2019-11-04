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

#include <cstdint>
#include <unordered_map>

#include "Version.h"

#if OSQUERY_VERSION_NUMBER < SDK_VERSION(4, 0)
#include <osquery/sdk.h>

static inline void insertRow(osquery::QueryData &result, osquery::Row &row) {
  result.push_back(row);
}
#else
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
static inline void insertRow(osquery::TableRows &result, osquery::Row &row) {
  result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
}
#endif

#include <rapidjson/document.h>

namespace trailofbits {
using PrimaryKey = std::string;
using RowID = std::uint64_t;
using RowIdToPrimaryKeyMap = std::unordered_map<RowID, PrimaryKey>;

class BaseTable : public osquery::TablePlugin {
 public:
  BaseTable() = default;
  virtual ~BaseTable() = default;

 protected:
  static osquery::Status ParseRowData(rapidjson::Document& document,
                                      const std::string& json_value_array) {
    document = {};
    document.Parse(json_value_array);
    if (document.HasParseError() || !document.IsArray()) {
      return osquery::Status(1, "Invalid format");
    }

    return osquery::Status(0, "OK");
  }
};
} // namespace trailofbits
