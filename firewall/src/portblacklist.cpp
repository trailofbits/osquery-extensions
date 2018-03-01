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
namespace {
using FirewallState = std::unordered_map<std::uint64_t,
                                         std::tuple<std::uint16_t,
                                                    IFirewall::TrafficDirection,
                                                    IFirewall::Protocol,
                                                    IFirewall::State>>;

std::uint64_t RuleToRowId(std::uint16_t port,
                          IFirewall::TrafficDirection direction,
                          IFirewall::Protocol protocol) {
  auto row_id = static_cast<std::uint64_t>(port);

  if (direction == IFirewall::TrafficDirection::Inbound) {
    row_id |= 0x10000ULL;
  } else {
    row_id |= 0x20000ULL;
  }

  if (protocol == IFirewall::Protocol::TCP) {
    row_id |= 0x40000ULL;
  } else {
    row_id |= 0x80000ULL;
  }

  return row_id;
}

void RowIdToRule(std::uint16_t& port,
                 IFirewall::TrafficDirection& direction,
                 IFirewall::Protocol& protocol,
                 std::uint64_t row_id) {
  port = (row_id & 0xFFFFULL);

  if ((row_id & 0x10000ULL) != 0) {
    direction = IFirewall::TrafficDirection::Inbound;
  } else {
    direction = IFirewall::TrafficDirection::Outbound;
  }

  if ((row_id & 0x40000ULL) != 0) {
    protocol = IFirewall::Protocol::TCP;
  } else {
    protocol = IFirewall::Protocol::UDP;
  }
}

bool GetFirewallState(FirewallState& firewall_state) {
  auto L_enumCallback = [](std::uint16_t port,
                           IFirewall::TrafficDirection direction,
                           IFirewall::Protocol protocol,
                           IFirewall::State state,
                           void* user_defined) -> bool {

    auto& firewall_state = *static_cast<FirewallState*>(user_defined);
    auto row_id = RuleToRowId(port, direction, protocol);

    // clang-format off
    firewall_state.insert(
      {row_id, {port, direction, protocol, state}}
    );
    // clang-format on

    return true;
  };

  auto status =
      firewall->enumerateBlacklistedPorts(L_enumCallback, &firewall_state);

  if (!status.success()) {
    std::cerr << __LINE__ << ": Failed to enumerate the firewall rules";

    firewall_state.clear();
    return false;
  }

  return true;
}
} // namespace

PortBlacklistTable::PortBlacklistTable() {}

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
  osquery::QueryData results;

  FirewallState firewall_state;
  if (!GetFirewallState(firewall_state)) {
    return results;
  }

  for (const auto& pair : firewall_state) {
    std::uint64_t row_id = pair.first;
    const auto& tuple = pair.second;

    std::uint16_t port = std::get<0>(tuple);
    IFirewall::TrafficDirection direction = std::get<1>(tuple);
    IFirewall::Protocol protocol = std::get<2>(tuple);
    IFirewall::State state = std::get<3>(tuple);

    osquery::Row row;
    row["rowid"] = std::to_string(row_id);
    row["port"] = std::to_string(port);
    row["direction"] = (direction == IFirewall::TrafficDirection::Inbound)
                           ? "INBOUND"
                           : "OUTBOUND";

    row["protocol"] = (protocol == IFirewall::Protocol::TCP ? "TCP" : "UDP");

    switch (state) {
    case IFirewall::State::Active: {
      row["status"] = "ACTIVE";
      break;
    }

    case IFirewall::State::Pending: {
      row["status"] = "PENDING";
      break;
    }

    case IFirewall::State::Error: {
      row["status"] = "ERROR";
      break;
    }

    default: {
      row["status"] = "UNKNOWN";
      break;
    }
    }

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

  std::uint16_t port;
  IFirewall::TrafficDirection direction;
  IFirewall::Protocol protocol;
  ParseInsertData(port, direction, protocol, row);

  // Ignore constraint errors
  auto fw_status = firewall->addPortToBlacklist(port, direction, protocol);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::AlreadyExists) {
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row result;
  result["id"] = std::to_string(RuleToRowId(port, direction, protocol));

  result["status"] = "success";
  return {result};
}

osquery::QueryData PortBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  unsigned long long row_id;
  auto status = osquery::safeStrtoull(request.at("id"), 10, row_id);
  if (!status.ok() || row_id == 0) {
    return {{std::make_pair("status", "failure")}};
  }

  std::uint16_t port;
  IFirewall::TrafficDirection direction;
  IFirewall::Protocol protocol;
  RowIdToRule(port, direction, protocol, row_id);

  auto fw_status = firewall->removePortFromBlacklist(port, direction, protocol);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::NotFound) {
    return {{std::make_pair("status", "failure")}};
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData PortBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  if (request.find("new_id") != request.end()) {
    std::cerr << "Unsupported statement with new_id set\n";
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

  std::uint16_t new_port;
  IFirewall::TrafficDirection new_direction;
  IFirewall::Protocol new_protocol;
  ParseInsertData(new_port, new_direction, new_protocol, row);

  unsigned long long row_id;
  status = osquery::safeStrtoull(request.at("id"), 10, row_id);
  if (!status.ok() || row_id == 0) {
    return {{std::make_pair("status", "failure")}};
  }

  std::uint16_t old_port;
  IFirewall::TrafficDirection old_direction;
  IFirewall::Protocol old_protocol;
  RowIdToRule(old_port, old_direction, old_protocol, row_id);

  auto fw_status =
      firewall->removePortFromBlacklist(old_port, old_direction, old_protocol);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::NotFound) {
    return {{std::make_pair("status", "failure")}};
  }

  // Ignore constraint errors
  fw_status =
      firewall->addPortToBlacklist(new_port, new_direction, new_protocol);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::AlreadyExists) {
    return {{std::make_pair("status", "failure")}};
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

  // We are going to ignore the fourth column, but make sure it's present and
  // empty
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

  static const std::vector<std::string> valid_protocols = {"TCP", "UDP"};

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
} // namespace trailofbits
