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

#include <osquery/logger.h>

#include "santa.h"
#include "santaeventstable.h"

REGISTER_EXTERNAL(SantaEventsTablePlugin, "table", "santa_events");

osquery::TableColumns SantaEventsTablePlugin::columns() const {
  // clang-format off
  return {
      std::make_tuple("timestamp",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("path",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("shasum",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("reason",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData SantaEventsTablePlugin::generate(
    osquery::QueryContext& request) {
  LogEntries log_entries;
  if (!scrapeSantaLog(log_entries)) {
    return {};
  }

  osquery::QueryData result;
  for (const auto& entry : log_entries) {
    osquery::Row row;
    row["timestamp"] = entry.timestamp;
    row["path"] = entry.application;
    row["shasum"] = entry.sha256;
    row["reason"] = entry.reason;

    result.push_back(std::move(row));
  }

  return result;
}
