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

#include "extension.h"
#include "santa.h"

REGISTER_EXTERNAL(SantaEventsTablePlugin, "table", "santa_events");
REGISTER_EXTERNAL(SantaRulesTablePlugin, "table", "santa_rules");

osquery::TableColumns SantaEventsTablePlugin::columns() const {
  // clang-format off
  return {
      std::make_tuple("timestamp",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("path",
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
  LogEntries response;

  try {
    scrapeSantaLog(response);

  } catch (const std::exception& e) {
    VLOG(1) << e.what();

    osquery::Row r;
    r["timestamp"] = r["application"] = r["reason"] = "error";

    return {r};
  }

  osquery::QueryData result;
  for (LogEntries::iterator iter = response.begin(); iter != response.end();
       ++iter) {
    osquery::Row r;
    r["timestamp"] = iter->timestamp;
    r["path"] = iter->application;
    r["reason"] = iter->reason;
    result.push_back(r);
  }

  return result;
}

osquery::TableColumns SantaRulesTablePlugin::columns() const {
  // clang-format off
  return {
      std::make_tuple("shasum",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("state",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("type",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)

  };
  // clang-format on
}

osquery::QueryData SantaRulesTablePlugin::generate(
    osquery::QueryContext& request) {
  RuleEntries response;

  try {
    collectSantaRules(response);

  } catch (const std::exception& e) {
    VLOG(1) << e.what();

    osquery::Row r;
    r["shasum"] = r["type"] = r["state"] = "error";

    return {r};
  }

  osquery::QueryData result;
  for (RuleEntries::iterator iter = response.begin(); iter != response.end();
       ++iter) {
    osquery::Row r;
    r["shasum"] = iter->shasum;
    r["state"] = iter->state;
    r["type"] = iter->type;
    result.push_back(r);
  }

  return result;
}
