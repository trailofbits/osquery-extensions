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
struct HostRule final {
  std::string address;
  std::string domain;
  std::string sinkhole;
};

using HostRuleMap = std::unordered_map<PrimaryKey, HostRule>;

class HostBlacklistTable final : public BaseTable {
 public:
  HostBlacklistTable();
  virtual ~HostBlacklistTable();

  osquery::TableColumns columns() const;

#if OSQUERY_VERSION_NUMBER < OSQUERY_SDK_VERSION(4, 0)
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

  static osquery::Status PrepareInsertData(osquery::Row& row);
  static bool IsInsertDataValid(const osquery::Row& row);

  static std::string GeneratePrimaryKey(const HostRule& rule);
  static RowID GenerateRowID();

  void loadConfiguration();
  void saveConfiguration();

 public:
  static osquery::Status DomainToAddress(std::string& address,
                                         const std::string& domain,
                                         bool use_ipv4);
  static osquery::Status AddressToDomain(std::string& domain,
                                         const std::string& address);
};
} // namespace trailofbits

// Export the class outside the namespace so that osquery can pick it up
using HostBlacklistTable = trailofbits::HostBlacklistTable;
