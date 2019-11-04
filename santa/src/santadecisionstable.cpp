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

#include "Version.h"
#include <osquery/logger.h>

#include "santa.h"
#include "santadecisionstable.h"

osquery::TableRows getTableRowsFromQueryData(osquery::QueryData& rows) {
  osquery::TableRows result;
  for (auto&& row : rows) {
#if OSQUERY_VERSION_NUMBER >= SDK_VERSION(4, 0)
    result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
#else
    result.push_back(row);
#endif
  }
  return result;
}

osquery::TableColumns decisionTablesColumns() {
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

osquery::QueryData decisionTablesGenerate(osquery::QueryContext& request,
                                          SantaDecisionType decision) {
  LogEntries log_entries;
  if (!scrapeSantaLog(log_entries, decision)) {
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

osquery::TableRows SantaAllowedDecisionsTablePlugin::generate(
    osquery::QueryContext& request) {
  auto rows = decisionTablesGenerate(request, decision);
  return getTableRowsFromQueryData(rows);
}

osquery::TableRows SantaDeniedDecisionsTablePlugin::generate(
    osquery::QueryContext& request) {
  auto rows = decisionTablesGenerate(request, decision);
  return getTableRowsFromQueryData(rows);
}

osquery::TableColumns SantaAllowedDecisionsTablePlugin::columns() const {
  return decisionTablesColumns();
}

osquery::TableColumns SantaDeniedDecisionsTablePlugin::columns() const {
  return decisionTablesColumns();
}
