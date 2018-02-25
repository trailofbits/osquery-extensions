/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include "hostblacklist.h"

#include <osquery/core/conversions.h>
#include <osquery/sdk.h>
#include <osquery/system.h>

namespace trailofbits {
osquery::TableColumns HostBlacklistTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("address", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("domain", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("sinkhole", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData HostBlacklistTable::generate(
    osquery::QueryContext& context) {
  return {};
}

osquery::QueryData HostBlacklistTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  osquery::Row result;
  if (request.at("auto_rowid") == "false") {
    result["id"] = "1";
  }

  result["status"] = "success";
  return {result};
}

osquery::QueryData HostBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  return {{std::make_pair("status", "success")}};
}

osquery::QueryData HostBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  return {{std::make_pair("status", "success")}};
}
} // namespace trailofbits
