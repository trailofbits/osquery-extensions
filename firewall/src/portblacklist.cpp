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
#include "globals.h"

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

  PortRuleMap data;
  RowIdToPrimaryKeyMap row_id_to_pkey;
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
  PortRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  PortRuleMap firewall_data;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = firewall->enumerateBlacklistedPorts(
      [](std::uint16_t port, IFirewall::TrafficDirection direction,
         IFirewall::Protocol protocol, void* user_defined) -> bool {

        auto &firewall_data = *static_cast<PortRuleMap*>(user_defined);

        PortRule rule = {port, direction, protocol};
        auto pkey = GeneratePrimaryKey(rule);

        firewall_data.insert({pkey, rule});
        return true;
      },

      &firewall_data
    );
    // clang-format on

    static_cast<void>(fw_status);
  }

  osquery::QueryData results;

  for (const auto& pair : table_row_id_to_pkey) {
    const auto& row_id = pair.first;
    const auto& pkey = pair.second;

    const auto& rule = table_data.at(pkey);

    osquery::Row row;
    row["rowid"] = std::to_string(row_id);
    row["port"] = std::to_string(rule.port);

    row["direction"] = (rule.direction == IFirewall::TrafficDirection::Inbound)
                           ? "INBOUND"
                           : "OUTBOUND";

    row["protocol"] =
        (rule.protocol == IFirewall::Protocol::TCP ? "TCP" : "UDP");

    if (firewall_data.count(pkey) != 0) {
      row["status"] = "ENABLED";
    } else {
      row["status"] = "DISABLED";
    }

    results.push_back(row);
  }

  RowID temp_row_id = 0x8000000000000000ULL;
  for (const auto& pair : firewall_data) {
    const auto& pkey = pair.first;
    const auto& rule = pair.second;

    if (table_data.count(pkey) != 0) {
      continue;
    }

    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id++);
    row["port"] = std::to_string(rule.port);
    row["status"] = "UNMANAGED";

    row["direction"] = (rule.direction == IFirewall::TrafficDirection::Inbound)
                           ? "INBOUND"
                           : "OUTBOUND";

    row["protocol"] =
        (rule.protocol == IFirewall::Protocol::TCP ? "TCP" : "UDP");

    results.push_back(row);
  }

  return results;
}

osquery::QueryData PortBlacklistTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  if (request.at("auto_rowid") != "false") {
    std::cerr << "Unsupported statement with auto_rowid enabled\n";
    return {{std::make_pair("status", "failure")}};
  }

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

  PortRule rule;
  ParseInsertData(rule.port, rule.direction, rule.protocol, row);

  auto primary_key = GeneratePrimaryKey(rule);

  std::lock_guard<std::mutex> lock(d->mutex);

  // Make sure we never generate constraint errors
  if (d->data.find(primary_key) != d->data.end()) {
    // clang-format off
    auto row_id_to_pkey_it = std::find_if(
      d->row_id_to_pkey.begin(),
      d->row_id_to_pkey.end(),

      [primary_key](const std::pair<RowID, std::string> &pair) -> bool {
        return (primary_key == std::get<1>(pair));
      }
    );
    // clang-format on

    osquery::Row result;
    result["id"] = std::to_string(row_id_to_pkey_it->first);

    result["status"] = "success";
    return {result};
  }

  auto row_id = GenerateRowID();

  d->data.insert({primary_key, rule});
  d->row_id_to_pkey.insert({row_id, primary_key});

  auto fw_status =
      firewall->addPortToBlacklist(rule.port, rule.direction, rule.protocol);
  if (!fw_status.success()) {
    std::cerr << "Failed to enable the port rule\n";
  }

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData PortBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  unsigned long long row_id;
  auto status = osquery::safeStrtoull(request.at("id"), 10, row_id);
  if (!status.ok()) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x8000000000000000ULL) != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  std::lock_guard<std::mutex> lock(d->mutex);

  auto row_id_to_pkey_it = d->row_id_to_pkey.find(row_id);
  if (row_id_to_pkey_it == d->row_id_to_pkey.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto primary_key = row_id_to_pkey_it->second;
  d->row_id_to_pkey.erase(row_id_to_pkey_it);

  auto rule_it = d->data.find(primary_key);
  if (rule_it == d->data.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto rule = rule_it->second;
  d->data.erase(rule_it);

  auto fw_status = firewall->removePortFromBlacklist(
      rule.port, rule.direction, rule.protocol);
  if (!fw_status.success()) {
    std::cerr << "Failed to remove the port rule\n";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData PortBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  unsigned long long row_id;
  auto status = osquery::safeStrtoull(request.at("id"), 10, row_id);
  if (!status.ok() || row_id == 0) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x8000000000000000ULL) != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row row;
  status = GetRowData(row, request.at("json_value_array"));
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

  PortRule new_rule;
  ParseInsertData(new_rule.port, new_rule.direction, new_rule.protocol, row);

  auto new_primary_key = GeneratePrimaryKey(new_rule);

  std::lock_guard<std::mutex> lock(d->mutex);

  auto row_id_to_pkey_it = d->row_id_to_pkey.find(row_id);
  if (row_id_to_pkey_it == d->row_id_to_pkey.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto original_primary_key = row_id_to_pkey_it->second;
  if (original_primary_key == new_primary_key) {
    return {{std::make_pair("status", "success")}};
  }

  if (d->data.find(new_primary_key) != d->data.end()) {
    return {{std::make_pair("status", "constraint")}};
  }

  auto original_rule_it = d->data.find(original_primary_key);
  if (original_rule_it == d->data.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto original_rule = original_rule_it->second;

  d->row_id_to_pkey.erase(row_id_to_pkey_it);
  d->data.erase(original_rule_it);

  auto fw_status = firewall->removePortFromBlacklist(
      original_rule.port, original_rule.direction, original_rule.protocol);
  if (!fw_status.success()) {
    std::cerr << "Failed to remove the port rule\n";
  }

  RowID new_row_id;
  auto new_row_id_it = request.find("new_id");
  if (new_row_id_it != request.end()) {
    // sqlite has generated the new rowid for us, so we'll discard
    // the one we have
    unsigned long long int temp;
    status = osquery::safeStrtoull(new_row_id_it->second, 10, temp);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure")}};
    }

    new_row_id = static_cast<RowID>(temp);

  } else {
    // Here we are supposed to keep the rowid we already have
    new_row_id = row_id;
  }

  d->data.insert({new_primary_key, new_rule});
  d->row_id_to_pkey.insert({new_row_id, new_primary_key});

  fw_status = firewall->addPortToBlacklist(
      new_rule.port, new_rule.direction, new_rule.protocol);
  if (!fw_status.success()) {
    std::cerr << "Failed to add the port rule\n";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::Status PortBlacklistTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  document.Parse(json_value_array);
  if (document.HasParseError() || !document.IsArray()) {
    return osquery::Status(1, "Invalid format");
  }

  // We are going to ignore the fourth column, but make sure it's present
  // so that we know if the schema is correct
  if (document.Size() != 4U) {
    return osquery::Status(1, "Wrong column count");
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

  static const std::vector<std::string> valid_directions = {"INBOUND",
                                                            "OUTBOUND"};

  const auto& direction = value_it->second;
  if (!L_validateValue(direction, valid_directions)) {
    return false;
  }

  value_it = row.find("protocol");
  if (value_it == row.end()) {
    return false;
  }

  static const std::vector<std::string> valid_protocols = {"TCP", "UDP"};

  const auto& protocol = value_it->second;
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

void PortBlacklistTable::ParseInsertData(std::uint16_t& port,
                                         IFirewall::TrafficDirection& direction,
                                         IFirewall::Protocol& protocol,
                                         const osquery::Row& valid_row) {
  unsigned long long numeric_port_value;
  auto status =
      osquery::safeStrtoull(valid_row.at("port"), 10, numeric_port_value);

  port = static_cast<std::uint16_t>(numeric_port_value);

  if (valid_row.at("direction") == "INBOUND") {
    direction = IFirewall::TrafficDirection::Inbound;
  } else {
    direction = IFirewall::TrafficDirection::Outbound;
  }

  if (valid_row.at("protocol") == "TCP") {
    protocol = IFirewall::Protocol::TCP;
  } else {
    protocol = IFirewall::Protocol::UDP;
  }
}

std::string PortBlacklistTable::GeneratePrimaryKey(const PortRule& rule) {
  std::stringstream primary_key;

  primary_key << rule.port;

  if (rule.direction == IFirewall::TrafficDirection::Inbound) {
    primary_key << "_in_";
  } else {
    primary_key << "_out_";
  }

  if (rule.protocol == IFirewall::Protocol::TCP) {
    primary_key << "tcp";
  } else {
    primary_key << "udp";
  }

  return primary_key.str();
}

RowID PortBlacklistTable::GenerateRowID() {
  std::uint64_t generator = 0ULL;

  generator = (generator + 1) & 0x7FFFFFFFFFFFFFFFULL;
  return generator;
}
} // namespace trailofbits
