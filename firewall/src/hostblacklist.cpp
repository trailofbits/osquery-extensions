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

#include "hostblacklist.h"
#include "globals.h"

#include <osquery/core/conversions.h>
#include <osquery/system.h>

#include <algorithm>
#include <iostream>
#include <mutex>

#include <boost/asio.hpp>
namespace b_asio = boost::asio;
namespace b_ip = boost::asio::ip;

namespace trailofbits {
struct HostBlacklistTable::PrivateData final {
  std::mutex mutex;

  HostRuleMap data;
  RowIdToPrimaryKeyMap row_id_to_pkey;
};

HostBlacklistTable::HostBlacklistTable() : d(new PrivateData) {}

HostBlacklistTable::~HostBlacklistTable() {}

osquery::TableColumns HostBlacklistTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("address", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("domain", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("sinkhole", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("firewall_block", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("dns_block", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

    std::make_tuple("address_type", osquery::TEXT_TYPE, osquery::ColumnOptions::HIDDEN)
  };
  // clang-format on
}

osquery::QueryData HostBlacklistTable::generate(
    osquery::QueryContext& context) {
  HostRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  std::set<std::string> firewall_blacklist;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = firewall->enumerateBlacklistedHosts(
      [](const std::string &host, void* user_defined) -> bool {

        auto &firewall_blacklist = *static_cast<std::set<std::string>*>(user_defined);
        firewall_blacklist.insert(host);

        return true;
      },

      &firewall_blacklist
    );
    // clang-format on

    static_cast<void>(fw_status);
  }

  osquery::QueryData results;

  // Add managed firewall and dns rules
  for (const auto& pair : table_row_id_to_pkey) {
    const auto& row_id = pair.first;
    const auto& pkey = pair.second;

    const auto& rule = table_data.at(pkey);

    osquery::Row row;
    row["rowid"] = std::to_string(row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = rule.address;
    row["domain"] = rule.domain;
    row["sinkhole"] = rule.sinkhole;

    auto fw_blacklist_it = firewall_blacklist.find(rule.address);
    if (fw_blacklist_it != firewall_blacklist.end()) {
      firewall_blacklist.erase(fw_blacklist_it);
      row["firewall_block"] = "ENABLED";
    } else {
      row["firewall_block"] = "DISABLED";
    }

    row["dns_block"] = "DISABLED";

    results.push_back(row);
  }

  // Add unmanaged firewall rules
  RowID temp_row_id = 0x8000000000000000ULL;
  for (const auto& host : firewall_blacklist) {
    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = host;
    row["domain"] = "";
    row["sinkhole"] = "";
    row["firewall_block"] = "UNMANAGED";
    row["dns_block"] = "DISABLED";

    results.push_back(row);
  }

  /// \todo Add unmanaged host rules
  return results;
}

osquery::QueryData HostBlacklistTable::insert(
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

  status = PrepareInsertData(row);
  if (!status.ok()) {
    std::cerr << status.getMessage() << std::endl;
    return {{std::make_pair("status", "failure")}};
  }

  if (!IsInsertDataValid(row)) {
    std::cerr << "Invalid insert data: ";
    for (const auto& pair : row) {
      std::cerr << pair.first << "=\"" << pair.second << "\" ";
    }
    std::cerr << std::endl;

    return {{std::make_pair("status", "failure")}};
  }

  HostRule rule;
  rule.address = row["address"];
  rule.domain = row["domain"];
  rule.sinkhole = row["sinkhole"];

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

  // Multiple domains may point to the same address
  auto fw_status = firewall->addHostToBlacklist(rule.address);
  if (!fw_status.success() &&
      fw_status.detail() == IFirewall::Detail::AlreadyExists) {
    std::cerr << "Failed to enable the firewall host rule\n";
  }

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData HostBlacklistTable::delete_(
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

  auto fw_status = firewall->removeHostFromBlacklist(rule.address);
  if (!fw_status.success()) {
    std::cerr << "Failed to remove the firewall host rule\n";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData HostBlacklistTable::update(
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

  status = PrepareInsertData(row);
  if (!status.ok()) {
    std::cerr << status.getMessage() << std::endl;
    return {{std::make_pair("status", "failure")}};
  }

  if (!IsInsertDataValid(row)) {
    std::cerr << "Invalid insert data: ";
    for (const auto& pair : row) {
      std::cerr << pair.first << "=\"" << pair.second << "\" ";
    }
    std::cerr << std::endl;

    return {{std::make_pair("status", "failure")}};
  }

  HostRule new_rule;
  new_rule.address = row["address"];
  new_rule.domain = row["domain"];
  new_rule.sinkhole = row["sinkhole"];

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

  auto fw_status = firewall->removeHostFromBlacklist(original_rule.address);
  if (!fw_status.success()) {
    std::cerr << "Failed to remove the firewall host rule\n";
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

  fw_status = firewall->addHostToBlacklist(new_rule.address);
  if (!fw_status.success()) {
    std::cerr << "Failed to add the firewall host rule\n";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::Status HostBlacklistTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  auto status = ParseRowData(document, json_value_array);
  if (!status.ok()) {
    return status;
  }

  // We are going to ignore the last 3 columns column, but make sure they
  // are present so that we know if the schema is correct
  if (document.Size() != 6U) {
    return osquery::Status(1, "Wrong column count");
  }

  row["address"] = document[0].IsNull() ? "" : document[0].GetString();
  row["domain"] = document[1].IsNull() ? "" : document[1].GetString();
  row["sinkhole"] =
      document[2].IsNull() ? "127.0.0.1" : document[2].GetString();

  row["address_type"] = document[5].IsNull() ? "" : document[5].GetString();
  if (row["address_type"] != "ipv4" && row["address_type"] != "ipv6") {
    row["address_type"] = "ipv4";
  }

  return osquery::Status(0, "OK");
}

osquery::Status HostBlacklistTable::PrepareInsertData(osquery::Row& row) {
  bool use_ipv4 = (row["address_type"] == "ipv4");

  // Get the address from the domain
  if (row["address"].empty() && !row["domain"].empty()) {
    auto status =
        DomainToAddress(row.at("address"), row.at("domain"), use_ipv4);
    if (!status.ok()) {
      return status;
    }
  }

  // Get the domain from the address
  else if (!row["address"].empty() && row["domain"].empty()) {
    auto status = AddressToDomain(row.at("domain"), row.at("address"));
    if (!status.ok()) {
      return status;
    }
  }

  return osquery::Status(0, "OK");
}

bool HostBlacklistTable::IsInsertDataValid(const osquery::Row& row) {
  auto value_it = row.find("address");
  if (value_it == row.end()) {
    return false;
  }

  auto address = value_it->second;
  if (address.empty()) {
    return false;
  }

  value_it = row.find("domain");
  if (value_it == row.end()) {
    return false;
  }

  auto domain = value_it->second;
  if (domain.empty()) {
    return false;
  }

  value_it = row.find("sinkhole");
  if (value_it == row.end()) {
    return false;
  }

  auto sinkhole = value_it->second;
  if (sinkhole.empty()) {
    return false;
  }

  /// \todo Validate address, domain, sinkhole
  return true;
}

std::string HostBlacklistTable::GeneratePrimaryKey(const HostRule& rule) {
  return rule.domain;
}

RowID HostBlacklistTable::GenerateRowID() {
  static std::uint64_t generator = 0ULL;

  generator = (generator + 1) & 0x7FFFFFFFFFFFFFFFULL;
  return generator;
}

osquery::Status HostBlacklistTable::DomainToAddress(std::string& address,
                                                    const std::string& domain,
                                                    bool use_ipv4) {
  address.clear();

  try {
    b_asio::io_service io_service;
    b_ip::tcp::resolver resolver(io_service);

    b_ip::tcp::resolver::query query(domain, "");

    b_ip::tcp::resolver::iterator end_it;
    for (auto resolver_it = resolver.resolve(query); resolver_it != end_it;
         resolver_it++) {
      auto endpoint = resolver_it->endpoint();

      const auto& address_obj = endpoint.address();
      if (address_obj.is_v4() == use_ipv4) {
        address = address_obj.to_string();
        break;
      }
    }

    if (address.empty()) {
      throw std::exception();
    }

    return osquery::Status(0, "OK");

  } catch (...) {
    return osquery::Status(1,
                           "Failed to resolve the following domain: " + domain);
  }
}

osquery::Status HostBlacklistTable::AddressToDomain(
    std::string& domain, const std::string& address) {
  domain.clear();

  try {
    b_asio::io_service io_service;
    b_ip::tcp::resolver resolver(io_service);

    auto dot_count = std::count(address.begin(), address.end(), '.');
    bool use_ipv4 = (dot_count == 3);

    b_ip::tcp::endpoint endpoint;
    if (use_ipv4) {
      auto ip_address = b_ip::address_v4::from_string(address);
      endpoint.address(ip_address);

    } else {
      auto ip_address = b_ip::address_v6::from_string(address);
      endpoint.address(ip_address);
    }

    auto resolver_it = resolver.resolve(endpoint);

    b_ip::tcp::resolver::iterator end_it;
    if (resolver_it == end_it) {
      throw std::exception();
    }

    domain = resolver_it->host_name();
    if (domain.empty()) {
      throw std::exception();
    }

    return osquery::Status(0, "OK");

  } catch (...) {
    return osquery::Status(
        1, "Failed to reverse lookup the following address: " + address);
  }
}
} // namespace trailofbits
