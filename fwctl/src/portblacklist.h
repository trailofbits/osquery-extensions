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

#include "basetable.h"

#include <trailofbits/ifirewall.h>

#include <memory>

namespace trailofbits {
struct PortRule final {
  std::uint16_t port;
  IFirewall::TrafficDirection direction;
  IFirewall::Protocol protocol;
};

using PortRuleMap = std::unordered_map<PrimaryKey, PortRule>;

class PortBlacklistTable final : public BaseTable {
 public:
  PortBlacklistTable();
  virtual ~PortBlacklistTable();

  osquery::TableColumns columns() const;

#if OSQUERY_VERSION_NUMBER <= 4000
  osquery::QueryData generate(osquery::QueryContext& context);
#else
  osquery::TableRows generate(osquery::QueryContext& context);
#endif

  osquery::QueryData insert(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

  osquery::QueryData delete_(osquery::QueryContext& context,
                             const osquery::PluginRequest& request);

  osquery::QueryData update(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  static osquery::Status GetRowData(osquery::Row& row,
                                    const std::string& json_value_array);

  static void PreprocessInsertData(osquery::Row& row);
  static bool IsInsertDataValid(const osquery::Row& row);
  static void SetDefaultValuesInInsertData(osquery::Row& valid_row);

  static void ParseInsertData(std::uint16_t& port,
                              IFirewall::TrafficDirection& direction,
                              IFirewall::Protocol& protocol,
                              const osquery::Row& valid_row);

  static std::string GeneratePrimaryKey(const PortRule& rule);
  static RowID GenerateRowID();

  void loadConfiguration();
  void saveConfiguration();
};
} // namespace trailofbits

// Export the class outside the namespace so that osquery can pick it up
using PortBlacklistTable = trailofbits::PortBlacklistTable;
