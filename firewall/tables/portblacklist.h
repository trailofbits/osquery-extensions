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

#pragma once

#include <osquery/sdk.h>

#include <cstdint>
#include <memory>

namespace trailofbits {
class PortBlacklistTable : public osquery::TablePlugin {
 public:
  PortBlacklistTable();
  virtual ~PortBlacklistTable();

  osquery::TableColumns columns() const;

  osquery::QueryData generate(osquery::QueryContext& context);

  osquery::QueryData insert(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

  osquery::QueryData delete_(osquery::QueryContext& context,
                             const osquery::PluginRequest& request);

  osquery::QueryData update(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  using PrimaryKey = std::string;
  using RowID = std::uint64_t;

  struct Rule final {
    enum class Direction { Inbound, Outbound };
    enum class Protocol { TCP, UDP, Others };
    enum class Status { Pending, Applied, Error };

    RowID rowid;
    std::uint16_t port;
    Direction direction;
    Protocol protocol;
    Status status;
  };

  using RuleMap = std::unordered_map<std::string, Rule>;

  RowID generateRowId();
  void saveRule(const Rule& rule, const PrimaryKey& primary_key);

  static osquery::Status GetRowData(osquery::Row& row,
                                    const std::string& json_value_array);

  static void PreprocessInsertData(osquery::Row& row);
  static bool IsInsertDataValid(const osquery::Row& row);
  static void SetDefaultValuesInInsertData(osquery::Row& valid_row);
  static Rule GenerateRuleFromInsertData(const osquery::Row& valid_row);

  static std::string GeneratePrimaryKeyForRule(const Rule& valid_rule);

  static bool CheckForConstraintErrors(const RuleMap& rule_map,
                                       const std::string& new_primary_key);
};
} // namespace trailofbits
