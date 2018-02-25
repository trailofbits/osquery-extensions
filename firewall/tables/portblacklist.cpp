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

#include "portblacklist.h"

#include <osquery/core/conversions.h>
#include <osquery/sdk.h>
#include <osquery/system.h>

#include <rapidjson/document.h>

#include <algorithm>
#include <iostream>
#include <mutex>
#include <unordered_map>

namespace trailofbits {
struct PortBlacklistTable::PrivateData final {
  std::mutex mutex;

  std::unordered_map<RowID, PrimaryKey> rowid_to_primary_key;
  RuleMap port_rules;
};

PortBlacklistTable::PortBlacklistTable() : d(new PrivateData) {}

PortBlacklistTable::~PortBlacklistTable() {}

osquery::TableColumns PortBlacklistTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("port", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("direction", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("protocol", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("status", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData PortBlacklistTable::generate(
    osquery::QueryContext& context) {
  std::lock_guard<std::mutex> lock(d->mutex);

  osquery::QueryData results;
  osquery::Row row;

  for (const auto& pair : d->port_rules) {
    const auto& rule = pair.second;

    row.clear();

    row["rowid"] = std::to_string(rule.rowid);
    row["port"] = std::to_string(rule.port);

    row["direction"] =
        (rule.direction == Rule::Direction::Inbound) ? "INBOUND" : "OUTBOUND";

    switch (rule.protocol) {
    case Rule::Protocol::TCP: {
      row["protocol"] = "TCP";
      break;
    }

    case Rule::Protocol::UDP: {
      row["protocol"] = "UDP";
      break;
    }

    case Rule::Protocol::Others: {
      row["protocol"] = "OTHERS";
      break;
    }
    }

    switch (rule.status) {
    case Rule::Status::Pending: {
      row["status"] = "PENDING";
      break;
    }

    case Rule::Status::Applied: {
      row["status"] = "APPLIED";
      break;
    }

    case Rule::Status::Error: {
      row["status"] = "ERROR";
      break;
    }
    }

    results.push_back(row);
  }

  return results;
}

osquery::QueryData PortBlacklistTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    std::cerr << status.getMessage() << std::endl;
    return {{std::make_pair("status", "failure")}};
  }

  PreprocessInsertData(row);
  if (!IsInsertDataValid(row)) {
    std::cerr << "Invalid insert data: ";
    for (const auto& pair : row) {
      std::cerr << pair.first << "=\"" << pair.second << "\" ";
    }
    std::cerr << std::endl;

    return {{std::make_pair("status", "failure")}};
  }

  SetDefaultValuesInInsertData(row);

  auto new_rule = GenerateRuleFromInsertData(row);
  auto new_primary_key = GeneratePrimaryKeyForRule(new_rule);

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    if (!CheckForConstraintErrors(d->port_rules, new_primary_key)) {
      return {{std::make_pair("status", "constraint")}};
    }

    if (request.at("auto_rowid") == "false") {
      new_rule.rowid = generateRowId();

    } else {
      unsigned long long int temp;
      status = osquery::safeStrtoull(request.at("id"), 10, temp);
      if (!status.ok()) {
        std::cerr << "Invalid rowid received by osquery";
        return {{std::make_pair("status", "failure")}};
      }

      new_rule.rowid = static_cast<RowID>(temp);
    }

    saveRule(new_rule, new_primary_key);
  }

  osquery::Row result;
  if (request.at("auto_rowid") == "false") {
    result["id"] = std::to_string(new_rule.rowid);
  }

  result["status"] = "success";
  return {result};
}

osquery::QueryData PortBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  return {{std::make_pair("status", "failure")}};
}

osquery::QueryData PortBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  return {{std::make_pair("status", "constraint")}};
}

PortBlacklistTable::RowID PortBlacklistTable::generateRowId() {
  static RowID generator = 0U;
  return generator++;
}

void PortBlacklistTable::saveRule(const Rule& rule,
                                  const PrimaryKey& primary_key) {
  d->port_rules.insert({primary_key, rule});
  d->rowid_to_primary_key.insert({rule.rowid, primary_key});
}

osquery::Status PortBlacklistTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  document.Parse(json_value_array);
  if (document.HasParseError() || !document.IsArray()) {
    return osquery::Status(1, "Invalid format");
  }

  // We are going to ignore the fourth column, but make sure it's present and
  // empty
  if (document.Size() != 4U) {
    return osquery::Status(1, "Wrong column count");
  }

  if (!document[3].IsNull()) {
    return osquery::Status(
        1, "The \"status\" column is read only and can't be inserted/updated");
  }

  row["port"] = std::to_string(document[0].IsNull() ? 0 : document[0].GetInt());

  row["direction"] = document[1].IsNull() ? "" : document[1].GetString();
  row["protocol"] = document[2].IsNull() ? "" : document[2].GetString();

  return osquery::Status(0, "OK");
}

void PortBlacklistTable::PreprocessInsertData(osquery::Row& row) {
  auto L_toUpper = [](std::string& str) -> void {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
  };

  for (auto& pair : row) {
    L_toUpper(pair.second);
  }
}

bool PortBlacklistTable::IsInsertDataValid(const osquery::Row& row) {
  // Make sure we have a valid port value
  auto value_it = row.find("port");
  if (value_it == row.end()) {
    return false;
  }

  const auto& port = value_it->second;
  if (port.empty() ||
      std::find_if_not(port.begin(), port.end(), ::isdigit) != port.end()) {
    return false;
  }

  unsigned long long numeric_port_value;
  auto status = osquery::safeStrtoull(port, 10, numeric_port_value);
  if (!status.ok() || numeric_port_value == 0) {
    return false;
  }

  // Validate the direction and protocol values
  auto L_validateValue = [](const std::string& str,
                            const std::vector<std::string>& options) -> bool {
    for (const auto& opt : options) {
      if (str == opt) {
        return true;
      }
    }

    return false;
  };

  value_it = row.find("direction");
  if (value_it == row.end()) {
    return false;
  }

  const auto& direction = value_it->second;

  static const std::vector<std::string> valid_directions = {"INBOUND",
                                                            "OUTBOUND"};

  if (!L_validateValue(direction, valid_directions)) {
    return false;
  }

  value_it = row.find("protocol");
  if (value_it == row.end()) {
    return false;
  }

  const auto& protocol = value_it->second;

  static const std::vector<std::string> valid_protocols = {
      "TCP", "UDP", "OTHERS"};

  if (!L_validateValue(protocol, valid_protocols)) {
    return false;
  }

  return true;
}

void PortBlacklistTable::SetDefaultValuesInInsertData(osquery::Row& valid_row) {
  if (valid_row["direction"].empty()) {
    valid_row["direction"] = "INBOUND";
  }

  if (valid_row["protocol"].empty()) {
    valid_row["protocol"] = "TCP";
  }
}

PortBlacklistTable::Rule PortBlacklistTable::GenerateRuleFromInsertData(
    const osquery::Row& valid_row) {
  Rule rule;

  if (valid_row.at("direction") == "INBOUND") {
    rule.direction = Rule::Direction::Inbound;
  } else if (valid_row.at("direction") == "OUTBOUND") {
    rule.direction = Rule::Direction::Outbound;
  }

  if (valid_row.at("protocol") == "TCP") {
    rule.protocol = Rule::Protocol::TCP;
  } else if (valid_row.at("protocol") == "UDP") {
    rule.protocol = Rule::Protocol::UDP;
  } else if (valid_row.at("protocol") == "OTHERS") {
    rule.protocol = Rule::Protocol::Others;
  }

  rule.status = Rule::Status::Pending;

  unsigned long long int port;
  auto status = osquery::safeStrtoull(valid_row.at("port"), 10, port);
  rule.port = static_cast<std::uint16_t>(port);

  return rule;
}

std::string PortBlacklistTable::GeneratePrimaryKeyForRule(
    const Rule& valid_rule) {
  std::stringstream str_helper;
  str_helper << valid_rule.port << "_";

  switch (valid_rule.direction) {
  case Rule::Direction::Inbound: {
    str_helper << "inbound";
    break;
  }

  case Rule::Direction::Outbound: {
    str_helper << "outbound";
    break;
  }
  }

  str_helper << "_";

  switch (valid_rule.protocol) {
  case Rule::Protocol::TCP: {
    str_helper << "tcp";
    break;
  }

  case Rule::Protocol::UDP: {
    str_helper << "udp";
    break;
  }

  case Rule::Protocol::Others: {
    str_helper << "others";
    break;
  }
  }

  return str_helper.str();
}

bool PortBlacklistTable::CheckForConstraintErrors(
    const RuleMap& rule_map, const std::string& new_primary_key) {
  return (rule_map.find(new_primary_key) == rule_map.end());
}

} // namespace trailofbits
