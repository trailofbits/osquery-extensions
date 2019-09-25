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

#include "portblacklist.h"
#include "globals.h"

#if OSQUERY_VERSION_NUMBER <= 4000
#include <osquery/core/conversions.h>
#else
#include <osquery/sql/dynamic_table_row.h>
#endif

#include <osquery/system.h>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/serialization/unordered_map.hpp>

#include <algorithm>
#include <iostream>
#include <mutex>

namespace b_fs = boost::filesystem;
namespace b_arc = boost::archive;

namespace boost {
namespace serialization {
template <class Archive>
void serialize(Archive& archive,
               trailofbits::PortRule& rule,
               const unsigned int version) {
  static_cast<void>(version);

  archive& rule.port;
  archive& rule.direction;
  archive& rule.protocol;
}
} // namespace serialization
} // namespace boost

namespace trailofbits {
struct PortBlacklistTable::PrivateData final {
  std::mutex mutex;

  PortRuleMap data;
  RowIdToPrimaryKeyMap row_id_to_pkey;

  b_fs::path configuration_file_path;
};

PortBlacklistTable::PortBlacklistTable() : d(new PrivateData) {
  d->configuration_file_path = CONFIGURATION_ROOT;
  d->configuration_file_path /= "portblacklist.cfg";

  loadConfiguration();
}

PortBlacklistTable::~PortBlacklistTable() {}

osquery::TableColumns PortBlacklistTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("port", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("direction", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("protocol", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("status", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

#if OSQUERY_VERSION_NUMBER <= 4000
osquery::QueryData PortBlacklistTable::generate(
    osquery::QueryContext& context) {
  static_cast<void>(context);

  PortRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  PortRuleMap firewall_data;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = GetFirewall().enumerateBlacklistedPorts(
      [](std::uint16_t port, IFirewall::TrafficDirection direction,
         IFirewall::Protocol protocol, void* user_defined) -> bool {

        auto &rule_list = *static_cast<PortRuleMap*>(user_defined);

        PortRule rule = {port, direction, protocol};
        auto pkey = GeneratePrimaryKey(rule);

        rule_list.insert({pkey, rule});
        return true;
      },

      &firewall_data
    );
    // clang-format on

    static_cast<void>(fw_status);
  }

  osquery::QueryData results;

  // Add managed firewall rules
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

  // Add unmanaged firewall rules
  RowID temp_row_id = 0x80000000ULL;
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
#else
osquery::TableRows PortBlacklistTable::generate(
    osquery::QueryContext& context) {
  static_cast<void>(context);

  PortRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  PortRuleMap firewall_data;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = GetFirewall().enumerateBlacklistedPorts(
      [](std::uint16_t port, IFirewall::TrafficDirection direction,
         IFirewall::Protocol protocol, void* user_defined) -> bool {

        auto &rule_list = *static_cast<PortRuleMap*>(user_defined);

        PortRule rule = {port, direction, protocol};
        auto pkey = GeneratePrimaryKey(rule);

        rule_list.insert({pkey, rule});
        return true;
      },

      &firewall_data
    );
    // clang-format on

    static_cast<void>(fw_status);
  }

  osquery::TableRows results;

  // Add managed firewall rules
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

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
  }

  // Add unmanaged firewall rules
  RowID temp_row_id = 0x80000000ULL;
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

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
  }

  return results;
}
#endif

osquery::QueryData PortBlacklistTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  if (request.at("auto_rowid") != "false") {
    VLOG(1) << "Unsupported statement with auto_rowid enabled";
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  PreprocessInsertData(row);
  if (!IsInsertDataValid(row)) {
    std::stringstream temp;
    temp << "Invalid insert data: ";
    for (const auto& pair : row) {
      temp << pair.first << "=\"" << pair.second << "\" ";
    }

    VLOG(1) << temp.str();
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

  auto fw_status = GetFirewall().addPortToBlacklist(
      rule.port, rule.direction, rule.protocol);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to enable the port rule";
  }

  saveConfiguration();

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData PortBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  char* null_term_ptr = nullptr;
  auto row_id = std::strtoull(request.at("id").c_str(), &null_term_ptr, 10);
  if (*null_term_ptr != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x80000000U) != 0) {
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
  saveConfiguration();

  auto fw_status = GetFirewall().removePortFromBlacklist(
      rule.port, rule.direction, rule.protocol);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to remove the port rule";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData PortBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  char* null_term_ptr = nullptr;
  auto row_id = std::strtoull(request.at("id").c_str(), &null_term_ptr, 10);
  if (*null_term_ptr != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x80000000U) != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  PreprocessInsertData(row);
  if (!IsInsertDataValid(row)) {
    std::stringstream temp;
    temp << "Invalid insert data: ";
    for (const auto& pair : row) {
      temp << pair.first << "=\"" << pair.second << "\" ";
    }

    VLOG(1) << temp.str();
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

  auto fw_status = GetFirewall().removePortFromBlacklist(
      original_rule.port, original_rule.direction, original_rule.protocol);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to remove the port rule";
  }

  RowID new_row_id;
  auto new_row_id_it = request.find("new_id");
  if (new_row_id_it != request.end()) {
    // sqlite has generated the new rowid for us, so we'll discard
    // the one we have
    const auto& new_row_id_string = new_row_id_it->second;

    null_term_ptr = nullptr;
    auto temp = std::strtoull(new_row_id_string.c_str(), &null_term_ptr, 10);
    if (*null_term_ptr != 0) {
      return {{std::make_pair("status", "failure")}};
    }

    new_row_id = static_cast<RowID>(temp);

  } else {
    // Here we are supposed to keep the rowid we already have
    new_row_id = row_id;
  }

  d->data.insert({new_primary_key, new_rule});
  d->row_id_to_pkey.insert({new_row_id, new_primary_key});
  saveConfiguration();

  fw_status = GetFirewall().addPortToBlacklist(
      new_rule.port, new_rule.direction, new_rule.protocol);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to add the port rule";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::Status PortBlacklistTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  auto status = ParseRowData(document, json_value_array);
  if (!status.ok()) {
    return status;
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
  auto L_convertStringToUppercase = [](std::string& str) -> void {
    auto L_toUpper = [](char c) -> char {
      return static_cast<char>(::toupper(c));
    };

    std::transform(str.begin(), str.end(), str.begin(), L_toUpper);
  };

  for (auto& pair : row) {
    L_convertStringToUppercase(pair.second);
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

  char* null_term_ptr = nullptr;
  auto numeric_port_value = std::strtoull(port.c_str(), &null_term_ptr, 10);
  if (*null_term_ptr != 0 || numeric_port_value == 0U ||
      numeric_port_value > 65535U) {
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
  auto numeric_port_value =
      std::strtoull(valid_row.at("port").c_str(), nullptr, 10);
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
  static std::uint32_t generator = 0U;

  generator = (generator + 1) & 0x7FFFFFFFU;
  return generator;
}

void PortBlacklistTable::loadConfiguration() {
  try {
    // Load the configuration file
    if (!b_fs::exists(d->configuration_file_path)) {
      return;
    }

    b_fs::ifstream configuration_file(d->configuration_file_path);
    if (!configuration_file) {
      return;
    }

    b_arc::text_iarchive archive(configuration_file);

    archive >> d->data;
    for (const auto& p : d->data) {
      auto row_id = GenerateRowID();
      auto primary_key = p.first;

      d->row_id_to_pkey.insert({row_id, primary_key});
    }

    // Re-apply each loaded rule
    for (const auto& pair : d->data) {
      const auto& rule = pair.second;

      auto fw_status = GetFirewall().addPortToBlacklist(
          rule.port, rule.direction, rule.protocol);

      if (!fw_status.success() &&
          fw_status.detail() != IFirewall::Detail::AlreadyExists) {
        std::stringstream temp;
        temp << "Failed to restore the following rule: " << rule.port << "/";

        if (rule.protocol == IFirewall::Protocol::TCP) {
          temp << "tcp ";
        } else {
          temp << "udp ";
        }

        if (rule.direction == IFirewall::TrafficDirection::Inbound) {
          temp << " (inbound)";
        } else {
          temp << " (outbound)";
        }

        VLOG(1) << temp.str();
      }
    }

  } catch (...) {
    VLOG(1) << "Failed to load the saved configuration";
  }
}

void PortBlacklistTable::saveConfiguration() {
  try {
    b_fs::ofstream configuration_file(d->configuration_file_path);
    if (!configuration_file) {
      return;
    }

    b_arc::text_oarchive archive(configuration_file);

    archive << d->data;

  } catch (...) {
    VLOG(1) << "Failed to save the configuration";
  }
}
} // namespace trailofbits
