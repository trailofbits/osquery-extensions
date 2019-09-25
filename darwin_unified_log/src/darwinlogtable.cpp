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

#if OSQUERY_VERSION_NUMBER > 4000
#include <osquery/sql/dynamic_table_row.h>
#endif

#include "system_log.h"
#include "darwinlogtable.h"

osquery::TableColumns UnifiedLogTablePlugin::columns() const {
  return {
    std::make_tuple("category",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("activityID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("eventType",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("processImageUUID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("processUniqueID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("threadID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("timestamp",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("traceID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("messageType",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("senderProgramCounter",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("processID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("machTimestamp",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("timezoneName",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("subsystem",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("eventMessage",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("senderImageUUID",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("processImagePath",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT),

    std::make_tuple("senderImagePath",
                    osquery::TEXT_TYPE,
                    osquery::ColumnOptions::DEFAULT)
  };
}

#if OSQUERY_VERSION_NUMBER <= 4000
osquery::QueryData UnifiedLogTablePlugin::generate(osquery::QueryContext& request) {
  osquery::QueryData q;
  logMonitor.getEntries(q);
  return q;
}
#else

osquery::TableRows getTableRowsFromQueryData(osquery::QueryData& rows) {
  osquery::TableRows result;
  for (auto&& row : rows) {
    result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
  }
  return result;
}

osquery::TableRows UnifiedLogTablePlugin::generate(osquery::QueryContext& request) {
  osquery::QueryData q;
  logMonitor.getEntries(q);
  return getTableRowsFromQueryData(q);
}
#endif


osquery::Status UnifiedLogTablePlugin::setUp() {
  return logMonitor.setUp();
}

void UnifiedLogTablePlugin::tearDown() {
  logMonitor.tearDown();
}

void UnifiedLogTablePlugin::configure() {
  logMonitor.configure();
}

